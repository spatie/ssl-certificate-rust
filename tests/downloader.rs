//! Real TLS handshakes over loopback; no public network dependencies.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::Arc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::{ServerConfig, ServerConnection, pki_types::PrivatePkcs8KeyDer};
use spatie_ssl_certificate::{Downloader, Error, SocketOptions, SslCertificate};
use tempfile::NamedTempFile;
use time::OffsetDateTime;

struct TestServer {
    address: SocketAddr,
    ca: NamedTempFile,
    leaf: Vec<u8>,
    handle: JoinHandle<Option<String>>,
}

fn server(
    expiration_offset: i64,
    start_offset: i64,
    duplicate: bool,
    ipv6: bool,
    tls12: bool,
) -> TestServer {
    let mut root_params = CertificateParams::default();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Test root");
    let root_key = KeyPair::generate().unwrap();
    let root = root_params.self_signed(&root_key).unwrap();
    let root_issuer = Issuer::new(root_params, root_key);

    let mut intermediate_params = CertificateParams::default();
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, "Test intermediate");
    let intermediate_key = KeyPair::generate().unwrap();
    let intermediate = intermediate_params
        .signed_by(&intermediate_key, &root_issuer)
        .unwrap();
    let issuer = Issuer::new(intermediate_params, intermediate_key);

    let now = OffsetDateTime::now_utc();
    let mut params =
        CertificateParams::new(vec!["spatie.test".into(), "127.0.0.1".into(), "::1".into()])
            .unwrap();
    params.not_before = now + time::Duration::days(start_offset);
    params.not_after = now + time::Duration::days(expiration_offset);
    params
        .distinguished_name
        .push(DnType::CommonName, "spatie.test");
    let key = KeyPair::generate().unwrap();
    let leaf = params.signed_by(&key, &issuer).unwrap();
    let mut chain = vec![leaf.der().clone(), intermediate.der().clone()];
    if duplicate {
        chain.push(intermediate.der().clone());
    }
    let version = if tls12 {
        &rustls::version::TLS12
    } else {
        &rustls::version::TLS13
    };
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, PrivatePkcs8KeyDer::from(key.serialize_der()).into())
            .unwrap();
    let listener = TcpListener::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" }).unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut connection = ServerConnection::new(Arc::new(config)).unwrap();
        while connection.is_handshaking() {
            if connection.complete_io(&mut stream).is_err() {
                break;
            }
        }
        connection.server_name().map(str::to_owned)
    });
    let mut ca = NamedTempFile::new().unwrap();
    ca.write_all(root.pem().as_bytes()).unwrap();
    TestServer {
        address,
        ca,
        leaf: leaf.der().to_vec(),
        handle,
    }
}

fn downloader(server: &TestServer) -> Downloader {
    Downloader::new()
        .with_ca_file(server.ca.path())
        .using_port(server.address.port())
        .from_ip_address(&server.address.ip().to_string())
        .unwrap()
        .set_timeout(Duration::from_secs(3))
}

fn certificate_error(error: &Error) -> &rustls::CertificateError {
    let tls = match error {
        Error::Tls(error) => error,
        Error::Io(error) => error
            .get_ref()
            .unwrap()
            .downcast_ref::<rustls::Error>()
            .unwrap(),
        other => panic!("expected TLS error, got {other}"),
    };
    match tls {
        rustls::Error::InvalidCertificate(error) => error,
        other => panic!("expected certificate error, got {other}"),
    }
}

#[test]
fn verifies_a_trusted_chain_and_preserves_sni_ip_and_remote_address() {
    let server = server(10, -1, false, false, false);
    let certificate = downloader(&server)
        .with_socket_context_options(SocketOptions {
            bind_address: Some("127.0.0.1:0".parse().unwrap()),
            tcp_nodelay: true,
            ..SocketOptions::default()
        })
        .for_host("spatie.test")
        .unwrap();
    assert_eq!(certificate.as_der(), server.leaf);
    assert_eq!(certificate.remote_address(), Some(server.address));
    assert_eq!(
        server.handle.join().unwrap().as_deref(),
        Some("spatie.test")
    );
}

#[test]
fn default_download_rejects_a_private_untrusted_ca() {
    let server = server(10, -1, false, false, false);
    let result = SslCertificate::create_for_host_name(&server.address.to_string());
    server.handle.join().unwrap();
    assert!(result.unwrap_err().to_string().contains("UnknownIssuer"));
}

#[test]
fn chain_downloads_are_leaf_first_and_unique() {
    let server = server(10, -1, true, false, false);
    let certificates = downloader(&server)
        .with_full_chain(true)
        .get_certificates("spatie.test")
        .unwrap();
    server.handle.join().unwrap();
    assert_eq!(certificates.len(), 2);
    assert_eq!(certificates[0].as_der(), server.leaf);
    assert_eq!(certificates[1].domain(), "Test intermediate");
    assert!(
        certificates
            .iter()
            .all(|c| c.remote_address() == Some(server.address))
    );
}

#[test]
fn default_chain_download_only_returns_the_leaf() {
    let server = server(10, -1, false, false, false);
    let certificates = downloader(&server).get_certificates("spatie.test").unwrap();
    server.handle.join().unwrap();
    assert_eq!(certificates.len(), 1);
    assert_eq!(certificates[0].as_der(), server.leaf);
}

#[test]
fn rejects_mismatched_names_unless_only_name_verification_is_disabled() {
    let first = server(10, -1, false, false, false);
    let error = downloader(&first).for_host("wrong.test").unwrap_err();
    first.handle.join().unwrap();
    assert!(matches!(
        certificate_error(&error),
        rustls::CertificateError::NotValidForName
            | rustls::CertificateError::NotValidForNameContext { .. }
    ));
    let second = server(10, -1, false, false, false);
    let certificate = downloader(&second)
        .with_verify_peer_name(false)
        .for_host("wrong.test")
        .unwrap();
    second.handle.join().unwrap();
    assert_eq!(certificate.domain(), "spatie.test");
}

#[test]
fn disabling_chain_verification_keeps_name_verification_enabled() {
    let first = server(10, -1, false, false, false);
    let result = downloader(&first)
        .with_verify_peer(false)
        .for_host("wrong.test");
    first.handle.join().unwrap();
    assert!(matches!(
        certificate_error(&result.unwrap_err()),
        rustls::CertificateError::NotValidForName
            | rustls::CertificateError::NotValidForNameContext { .. }
    ));
    let second = server(10, -1, false, false, false);
    let certificate = Downloader::new()
        .using_port(second.address.port())
        .from_ip_address("127.0.0.1")
        .unwrap()
        .with_verify_peer(false)
        .for_host("spatie.test")
        .unwrap();
    second.handle.join().unwrap();
    assert_eq!(certificate.domain(), "spatie.test");
}

#[test]
fn expired_and_not_yet_valid_certificates_fail_with_chain_verification() {
    for (end, start) in [(-1, -10), (10, 1)] {
        let server = server(end, start, false, false, false);
        let error = downloader(&server).for_host("spatie.test").unwrap_err();
        server.handle.join().unwrap();
        if end < 0 {
            assert!(matches!(
                certificate_error(&error),
                rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. }
            ));
        } else {
            assert!(matches!(
                certificate_error(&error),
                rustls::CertificateError::NotValidYet
                    | rustls::CertificateError::NotValidYetContext { .. }
            ));
        }
    }
}

#[test]
fn disabling_name_verification_does_not_disable_chain_or_expiry_checks() {
    let server = server(-1, -10, false, false, false);
    let error = downloader(&server)
        .with_verify_peer_name(false)
        .for_host("wrong.test")
        .unwrap_err();
    server.handle.join().unwrap();
    assert!(matches!(
        certificate_error(&error),
        rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. }
    ));
}

#[test]
fn explicit_opt_out_can_download_an_expired_certificate_over_tls12() {
    let server = server(-1, -10, false, false, true);
    let certificate = Downloader::download_certificate_from_url(
        &server.address.to_string(),
        Duration::from_secs(3),
        false,
    )
    .unwrap();
    server.handle.join().unwrap();
    assert_eq!(certificate.as_der(), server.leaf);
    assert!(certificate.is_expired());
}

#[test]
fn sni_can_be_disabled_without_disabling_name_verification() {
    let server = server(10, -1, false, false, false);
    let certificate = downloader(&server)
        .using_sni(false)
        .for_host("spatie.test")
        .unwrap();
    assert_eq!(server.handle.join().unwrap(), None);
    assert_eq!(certificate.domain(), "spatie.test");
}

#[test]
fn explicit_url_port_wins_and_ipv6_addresses_are_supported() {
    let server = server(10, -1, false, true, false);
    let certificate = downloader(&server)
        .using_port(1)
        .with_socket_context_options(SocketOptions {
            bind_address: Some("[::1]:0".parse().unwrap()),
            ipv6_only: Some(true),
            ..SocketOptions::default()
        })
        .for_host(&format!(
            "https://spatie.test:{}/path",
            server.address.port()
        ))
        .unwrap();
    server.handle.join().unwrap();
    assert_eq!(certificate.remote_address(), Some(server.address));
    assert!(certificate.applies_to_url("::1"));
}

#[test]
fn invalid_options_fail_before_connecting() {
    assert!(matches!(
        Downloader::new().from_ip_address("invalid"),
        Err(Error::InvalidIpAddress(_))
    ));
    assert!(matches!(
        Downloader::new().for_host(""),
        Err(Error::InvalidUrl(_))
    ));
    let ca = NamedTempFile::new().unwrap();
    assert!(matches!(
        Downloader::new()
            .with_ca_file(ca.path())
            .for_host("spatie.test"),
        Err(Error::NoTrustedRoots(_))
    ));
    assert!(matches!(
        Downloader::new()
            .with_ca_file("missing-ca.pem")
            .for_host("spatie.test"),
        Err(Error::Io(_))
    ));
    assert!(matches!(
        Downloader::new()
            .set_timeout(Duration::ZERO)
            .for_host("spatie.test"),
        Err(Error::Io(_))
    ));
}

#[test]
fn the_handshake_deadline_also_limits_a_trickling_server() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buffer = [0; 4096];
        let _ = stream.read(&mut buffer);
        // A partial TLS record, sent often enough to defeat an idle timeout.
        for byte in [22, 3, 3, 0, 100]
            .into_iter()
            .chain(std::iter::repeat_n(0, 50))
        {
            if stream.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
    let start = Instant::now();
    let result = Downloader::download_certificate_from_url(
        &address.to_string(),
        Duration::from_millis(150),
        false,
    );
    let elapsed = start.elapsed();
    handle.join().unwrap();
    let Err(Error::Io(error)) = result else {
        panic!("expected timeout")
    };
    assert!(
        matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ),
        "{error}"
    );
    assert!(
        elapsed < Duration::from_millis(800),
        "deadline exceeded: {elapsed:?}"
    );
}

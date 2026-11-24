//! Certificate queries through the public API, using the PHP package's fixtures.

use rcgen::{CertificateParams, CustomExtension, DnType, KeyPair};
use spatie_ssl_certificate::{CertificateProperties, Error, SslCertificate, Url};
use time::{Duration, OffsetDateTime};

fn fixture() -> SslCertificate {
    SslCertificate::create_from_string(include_str!("fixtures/spatieCertificate.pem")).unwrap()
}

#[test]
fn reads_the_php_pem_fixture_metadata() {
    let certificate = fixture();
    assert_eq!(certificate.issuer(), "Let's Encrypt Authority X3");
    assert_eq!(certificate.organization(), "Let's Encrypt");
    assert_eq!(certificate.subject_organization(), "");
    assert_eq!(certificate.domain(), "analytics.spatie.be");
    assert_eq!(certificate.signature_algorithm(), "RSA-SHA256");
    assert_eq!(certificate.public_key_algorithm(), "RSA");
    assert_eq!(certificate.public_key_size(), 4096);
    assert_eq!(
        certificate.serial_number(),
        "336899711758849282197364764510982704635866"
    );
    assert_eq!(
        certificate.raw_certificate_fields().serial_number_hex,
        "03DE0F2C502C8A71EC30E56708B6C44E9FDA"
    );
    assert_eq!(
        certificate.valid_from_date().unix_timestamp(),
        1_578_885_493
    );
    assert_eq!(
        certificate.expiration_date().unix_timestamp(),
        1_586_661_493
    );
    assert_eq!(certificate.lifespan_in_days(), 90);
    assert_eq!(certificate.domains(), ["analytics.spatie.be"]);
    assert_eq!(certificate.remote_address(), None);
    assert!(!certificate.is_self_signed());
    assert!(!certificate.uses_sha1_hash());
    assert!(!certificate.is_pre_certificate());
}

#[test]
fn fingerprints_match_independent_openssl_digests() {
    let certificate = fixture();
    assert_eq!(
        certificate.fingerprint(),
        "c02ca600c6e15026db5a5e3fe543f8e590e6c10a"
    );
    assert_eq!(
        certificate.fingerprint_sha256(),
        "cc376a127fb9f9444e64b69038a6ca43503a43a1e085e508d939adbf1bfd17ce"
    );
}

#[test]
fn reads_pem_and_der_files_and_round_trips_the_original_bytes() {
    let pem = SslCertificate::create_from_file(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/spatieCertificate.pem"
    ))
    .unwrap();
    assert_eq!(pem, fixture());
    assert_eq!(
        SslCertificate::create_from_string(&pem.to_pem()).unwrap(),
        pem
    );
    let der = SslCertificate::create_from_file(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/derCertificate.der"
    ))
    .unwrap();
    assert_eq!(der.as_der(), include_bytes!("fixtures/derCertificate.der"));
    assert_eq!(
        SslCertificate::create_from_string(&der.to_pem()).unwrap(),
        der
    );
}

#[test]
fn pem_bundles_select_the_first_certificate() {
    let bundle = format!(
        "{}{}",
        include_str!("fixtures/spatieCertificate.pem"),
        include_str!("fixtures/gtsRootR4.pem")
    );
    assert_eq!(
        SslCertificate::create_from_string(&bundle).unwrap(),
        fixture()
    );
}

#[test]
fn validity_includes_both_boundaries_but_not_adjacent_instants() {
    let certificate = fixture();
    for (seconds, expected) in [
        (1_578_885_492, false),
        (1_578_885_493, true),
        (1_586_661_493, true),
        (1_586_661_494, false),
    ] {
        assert_eq!(
            certificate.is_valid_at(OffsetDateTime::from_unix_timestamp(seconds).unwrap(), None),
            expected,
            "at {seconds}"
        );
    }
    let end = certificate.expiration_date();
    assert!(!certificate.is_expired_at(end));
    assert!(certificate.is_expired_at(end + Duration::nanoseconds(1)));
    let valid = OffsetDateTime::from_unix_timestamp(1_582_000_000).unwrap();
    assert!(certificate.is_valid_at(valid, Some("https://ANALYTICS.SPATIE.BE/path")));
    assert!(!certificate.is_valid_at(valid, Some("spatie.be")));
}

#[test]
fn day_counts_are_signed_and_truncate_toward_zero() {
    let certificate = fixture();
    let end = certificate.expiration_date();
    for (offset, days) in [(-172_801, 2), (-86_399, 0), (86_399, 0), (172_801, -2)] {
        assert_eq!(
            certificate.days_until_expiration_date_at(end + Duration::seconds(offset)),
            days
        );
    }
}

#[test]
fn valid_until_requires_current_validity_and_a_strictly_later_expiry() {
    let mut params = CertificateParams::new(vec!["spatie.be".into()]).unwrap();
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(10);
    let key = KeyPair::generate().unwrap();
    let certificate = SslCertificate::from_der(params.self_signed(&key).unwrap().der()).unwrap();
    assert!(certificate.is_valid(None));
    assert!(!certificate.is_expired());
    assert!(certificate.is_valid_until(now + Duration::days(7), Some("spatie.be")));
    assert!(!certificate.is_valid_until(certificate.expiration_date(), None));
    assert!(!certificate.is_valid_until(now + Duration::days(7), Some("example.com")));
    assert!(!fixture().is_valid_until(now - Duration::days(5000), None));
}

#[test]
fn hostname_matching_limits_wildcards_and_keeps_ip_addresses_typed() {
    let mut params = CertificateParams::new(vec![
        "SPATIE.BE".into(),
        "*.otherdomain.com".into(),
        "127.0.0.1".into(),
        "2001:db8::1".into(),
        "xn--hpfburg-n2a.de".into(),
    ])
    .unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "www.spatie.be");
    let key = KeyPair::generate().unwrap();
    let certificate = SslCertificate::from_der(params.self_signed(&key).unwrap().der()).unwrap();
    for host in [
        "spatie.be",
        "HTTPS://spatie.be",
        "www.spatie.be",
        "a.otherdomain.com",
        "https://a.otherdomain.com:443/path",
        "127.0.0.1",
        "2001:0db8::1",
        "https://[2001:db8::1]/",
        "https://hüpfburg.de",
    ] {
        assert!(
            certificate.applies_to_url(host),
            "expected coverage for {host}"
        );
    }
    for host in [
        "otherdomain.com",
        "a.b.otherdomain.com",
        "evilotherdomain.com",
        "spatie.be.facebook.com",
        "notreallyspatie.be",
        "",
        "https://",
        "127.0.0.2",
        "2001:db8::2",
    ] {
        assert!(
            !certificate.applies_to_url(host),
            "unexpected coverage for {host}"
        );
    }
    assert!(certificate.contains_domain("child.www.spatie.be"));
    assert!(!certificate.contains_domain("a.otherdomain.com"));
    assert!(!certificate.contains_domain("spatie.be"));
    assert!(!certificate.contains_domain("notreallywww.spatie.be"));
}

#[test]
fn missing_names_are_empty_and_domains_are_unique() {
    let mut params = CertificateParams::new(vec!["spatie.be".into(), "spatie.be".into()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key = KeyPair::generate().unwrap();
    let certificate = SslCertificate::from_der(params.self_signed(&key).unwrap().der()).unwrap();
    assert_eq!(certificate.domain(), "");
    assert_eq!(certificate.issuer(), "");
    assert_eq!(certificate.organization(), "");
    assert_eq!(certificate.domains(), ["spatie.be"]);
}

#[test]
fn elliptic_curve_metadata_and_the_self_signed_name_heuristic_are_recognized() {
    let certificate =
        SslCertificate::create_from_string(include_str!("fixtures/gtsRootR4.pem")).unwrap();
    assert_eq!(certificate.public_key_algorithm(), "EC");
    assert_eq!(certificate.public_key_size(), 384);
    assert_eq!(certificate.signature_algorithm(), "ecdsa-with-SHA384");
    assert!(certificate.is_self_signed());
    let mut corrupted = certificate.as_der().to_vec();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(
        SslCertificate::from_der(&corrupted)
            .unwrap()
            .is_self_signed()
    );
}

#[test]
fn reads_sha1_dsa_and_p521_certificates_without_using_them_as_tls_peers() {
    let sha1 = SslCertificate::create_from_string(include_str!("fixtures/sha1.pem")).unwrap();
    assert!(sha1.uses_sha1_hash());
    assert_eq!(sha1.signature_algorithm(), "RSA-SHA1");
    let dsa = SslCertificate::create_from_string(include_str!("fixtures/dsa.pem")).unwrap();
    assert_eq!(dsa.public_key_algorithm(), "DSA");
    assert_eq!(dsa.public_key_size(), 2048);
    let p521 = SslCertificate::create_from_string(include_str!("fixtures/p521.pem")).unwrap();
    assert_eq!(p521.public_key_algorithm(), "EC");
    assert_eq!(p521.public_key_size(), 521);
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = CertificateParams::new(vec!["ed25519.example".into()]).unwrap();
    let ed25519 = SslCertificate::from_der(params.self_signed(&key).unwrap().der()).unwrap();
    assert_eq!(ed25519.public_key_algorithm(), "Ed25519");
    assert_eq!(ed25519.public_key_size(), 256);
}

#[test]
fn recognizes_precertificates_without_dropping_unknown_extensions() {
    let mut params = CertificateParams::new(vec!["spatie.be".into()]).unwrap();
    let mut poison =
        CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 3], vec![5, 0]);
    poison.set_criticality(true);
    params.custom_extensions.push(poison);
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 2, 3, 4],
            vec![4, 2, 42, 43],
        ));
    let key = KeyPair::generate().unwrap();
    let certificate = SslCertificate::from_der(params.self_signed(&key).unwrap().der()).unwrap();
    assert!(certificate.is_pre_certificate());
    let extension = certificate
        .raw_certificate_fields()
        .extensions
        .iter()
        .find(|e| e.oid == "1.2.3.4")
        .unwrap();
    assert_eq!(extension.value, [4, 2, 42, 43]);
}

#[test]
fn properties_and_serde_round_trip_without_trusting_derived_fields() {
    let certificate = fixture();
    let mut properties = certificate.to_array();
    properties.remote_address = Some("[::1]:443".parse().unwrap());
    let restored = SslCertificate::create_from_array(properties).unwrap();
    let encoded = serde_json::to_string(&restored).unwrap();
    assert_eq!(
        serde_json::from_str::<SslCertificate>(&encoded).unwrap(),
        restored
    );
    assert_eq!(restored.remote_address().unwrap().to_string(), "[::1]:443");
    assert_eq!(
        restored.fingerprint_sha256(),
        certificate.fingerprint_sha256()
    );
    assert_eq!(
        certificate.to_string(),
        certificate.raw_certificate_fields_json()
    );
    let json: serde_json::Value = serde_json::from_str(&certificate.to_string()).unwrap();
    assert_eq!(json["subject"]["2.5.4.3"][0], "analytics.spatie.be");
    assert_eq!(json["valid_from"], 1_578_885_493);
    assert_eq!(certificate.hash().len(), 32);
    let invalid = CertificateProperties {
        der: vec![1, 2, 3],
        remote_address: None,
    };
    assert!(SslCertificate::create_from_array(invalid.clone()).is_err());
    assert!(
        serde_json::from_value::<SslCertificate>(serde_json::to_value(invalid).unwrap()).is_err()
    );
}

#[test]
fn rejects_malformed_missing_and_trailing_certificate_data() {
    for der in [b"".as_slice(), b"not a certificate", &[0x30, 0x80, 0]] {
        assert!(SslCertificate::from_der(der).is_err());
    }
    assert!(matches!(
        SslCertificate::create_from_string(""),
        Err(Error::NoCertificate)
    ));
    assert!(
        SslCertificate::create_from_string(
            "-----BEGIN CERTIFICATE-----\n!not-base64\n-----END CERTIFICATE-----"
        )
        .is_err()
    );
    let mut der = fixture().as_der().to_vec();
    der.push(0);
    assert!(SslCertificate::from_der(&der).is_err());
    assert!(SslCertificate::create_from_file("no-such-certificate.pem").is_err());
}

#[test]
fn parses_hosts_ports_ipv6_idna_and_long_paths() {
    for (input, host, port) in [
        ("https://spatie.be/opensource", "spatie.be", 443),
        ("spatie.be", "spatie.be", 443),
        ("http://spatie.be", "spatie.be", 443),
        ("http://spatie.be:80", "spatie.be", 80),
        ("ssl://spatie.be:12345", "spatie.be", 12345),
        ("spatie.be:443", "spatie.be", 443),
        (
            "https://www.hüpfburg.de:8443",
            "www.xn--hpfburg-n2a.de",
            8443,
        ),
        ("https://[::1]:8443/path", "::1", 8443),
        ("[::1]", "::1", 443),
    ] {
        let url = Url::new(input).unwrap();
        assert_eq!((url.host_name(), url.port()), (host, port));
    }
    assert_eq!(
        Url::new(&format!("https://random.host/{}", "path/".repeat(100)))
            .unwrap()
            .host_name(),
        "random.host"
    );
    for input in [
        "",
        "https://",
        "a b",
        "https://:443",
        "host:65536",
        "host:-1",
        "host:",
        "ftp://spatie.be",
        "https://user:pass@spatie.be",
    ] {
        assert!(Url::new(input).is_err(), "accepted {input}");
    }
}

use std::{
    fs,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor, verify_server_name,
    },
    crypto::{ring, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
    server::ParsedCertificate,
};
use socket2::{Domain, Protocol, Socket, Type};

use crate::{Error, SslCertificate, Url};

/// Typed TCP socket options, replacing PHP's socket context array.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SocketOptions {
    /// Local address and port to bind before connecting (`bindto` in PHP).
    pub bind_address: Option<SocketAddr>,
    /// Set `IPV6_V6ONLY` on IPv6 sockets before connecting.
    pub ipv6_only: Option<bool>,
    /// Enable TCP_NODELAY.
    pub tcp_nodelay: bool,
    /// Enable SO_REUSEADDR before binding.
    pub reuse_address: bool,
}

/// Downloads a leaf certificate or the chain sent by a TLS server.
///
/// Chain and hostname verification are on by default. The timeout covers TCP
/// connection attempts and the TLS handshake together, after synchronous DNS
/// resolution. No HTTP request is sent, so redirects are never followed.
#[derive(Clone, Debug)]
#[must_use]
pub struct Downloader {
    port: u16,
    ip_address: Option<IpAddr>,
    timeout: Duration,
    enable_sni: bool,
    full_chain: bool,
    verify_peer: bool,
    verify_peer_name: bool,
    ca_file: Option<PathBuf>,
    socket_options: SocketOptions,
}

impl Default for Downloader {
    fn default() -> Self {
        Self {
            port: 443,
            ip_address: None,
            timeout: Duration::from_secs(30),
            enable_sni: true,
            full_chain: false,
            verify_peer: true,
            verify_peer_name: true,
            ca_file: None,
            socket_options: SocketOptions::default(),
        }
    }
}

impl Downloader {
    /// Creates a downloader with system trust roots and a 30-second timeout.
    pub fn new() -> Self {
        Self::default()
    }

    /// Selects a port. An explicit port in the host URL takes precedence.
    pub fn using_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Enables or disables SNI without changing certificate name verification.
    pub fn using_sni(mut self, enabled: bool) -> Self {
        self.enable_sni = enabled;
        self
    }

    /// Includes the complete peer-supplied chain in [`Self::get_certificates`].
    /// The leaf is first; duplicate certificates are removed. Roots are usually
    /// not sent by servers and are not added from the local trust store.
    pub fn with_full_chain(mut self, enabled: bool) -> Self {
        self.full_chain = enabled;
        self
    }

    /// Enables or disables certificate chain verification.
    ///
    /// **Danger:** disabling this permits untrusted and expired certificates.
    /// Name checking remains enabled unless disabled separately. Handshake
    /// signatures are always verified by rustls.
    pub fn with_verify_peer(mut self, enabled: bool) -> Self {
        self.verify_peer = enabled;
        self
    }

    /// Enables or disables peer name verification independently of chain checks.
    ///
    /// **Danger:** disabling this accepts a trusted certificate for another host.
    pub fn with_verify_peer_name(mut self, enabled: bool) -> Self {
        self.verify_peer_name = enabled;
        self
    }

    /// Replaces system roots with the certificates in a PEM CA bundle.
    pub fn with_ca_file(mut self, path: impl AsRef<Path>) -> Self {
        self.ca_file = Some(path.as_ref().to_owned());
        self
    }

    /// Sets the TCP connection and TLS handshake timeout. Zero is invalid.
    pub fn set_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Configures the local bind address and TCP socket options.
    pub fn with_socket_context_options(mut self, options: SocketOptions) -> Self {
        self.socket_options = options;
        self
    }

    /// Connects to an IP address while retaining the host for SNI and verification.
    ///
    /// # Errors
    /// Returns [`Error::InvalidIpAddress`] for invalid IPv4 or IPv6 text.
    pub fn from_ip_address(mut self, ip: &str) -> Result<Self, Error> {
        self.ip_address = Some(ip.parse()?);
        Ok(self)
    }

    /// Downloads a host's leaf certificate, using this downloader's options.
    ///
    /// # Errors
    /// Returns an error for invalid input, DNS, network, TLS, or parsing failures.
    pub fn for_host(&self, host: &str) -> Result<SslCertificate, Error> {
        self.get_certificates(host)?
            .into_iter()
            .next()
            .ok_or(Error::NoCertificate)
    }

    /// Downloads the leaf, or the peer-supplied chain when requested.
    ///
    /// # Errors
    /// Returns an error for invalid input, empty trust stores, DNS, network,
    /// TLS verification, handshake timeout, or malformed certificates.
    pub fn get_certificates(&self, host: &str) -> Result<Vec<SslCertificate>, Error> {
        let url = Url::new(host)?;
        let server_name = ServerName::try_from(url.host_name().to_owned())
            .map_err(|_| Error::InvalidUrl(host.to_owned()))?;
        let config = self.client_config()?;
        let port = url.explicit_port().unwrap_or(self.port);
        let addresses = if let Some(ip) = self.ip_address {
            vec![SocketAddr::new(ip, port)]
        } else {
            (url.host_name(), port)
                .to_socket_addrs()
                .map_err(|_| Error::HostDoesNotExist(url.host_name().to_owned()))?
                .collect::<Vec<_>>()
        };
        if addresses.is_empty() {
            return Err(Error::HostDoesNotExist(url.host_name().to_owned()));
        }
        let start = Instant::now();
        let mut last_error =
            io::Error::new(io::ErrorKind::NotConnected, "no compatible socket address");
        let mut connected = None;
        for address in addresses {
            match self.connect(address, remaining(start, self.timeout)?) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(error) => last_error = error,
            }
        }
        let stream = connected.ok_or(last_error)?;
        let address = stream.peer_addr()?;
        let mut stream = DeadlineStream {
            stream,
            start,
            timeout: self.timeout,
        };
        let mut connection = ClientConnection::new(Arc::new(config), server_name)?;
        while connection.is_handshaking() {
            connection.complete_io(&mut stream)?;
        }
        let chain = connection.peer_certificates().ok_or(Error::NoCertificate)?;
        let mut certificates: Vec<SslCertificate> = Vec::new();
        for der in chain
            .iter()
            .take(if self.full_chain { chain.len() } else { 1 })
        {
            if certificates
                .iter()
                .any(|certificate| certificate.as_der() == der.as_ref())
            {
                continue;
            }
            let mut certificate = SslCertificate::from_der(der.as_ref())?;
            certificate.set_remote_address(address);
            certificates.push(certificate);
        }
        Ok(certificates)
    }

    /// Downloads a leaf certificate with explicit timeout and verification mode.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::for_host`]. Disabling verification
    /// disables both chain and peer name checks and is unsafe for authentication.
    pub fn download_certificate_from_url(
        url: &str,
        timeout: Duration,
        verify_certificate: bool,
    ) -> Result<SslCertificate, Error> {
        Self::new()
            .set_timeout(timeout)
            .with_verify_peer(verify_certificate)
            .with_verify_peer_name(verify_certificate)
            .for_host(url)
    }

    fn connect(&self, address: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        let socket = Socket::new(
            Domain::for_address(address),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        socket.set_reuse_address(self.socket_options.reuse_address)?;
        if address.is_ipv6()
            && let Some(only) = self.socket_options.ipv6_only
        {
            socket.set_only_v6(only)?;
        }
        if let Some(bind) = self.socket_options.bind_address {
            socket.bind(&bind.into())?;
        }
        socket.set_tcp_nodelay(self.socket_options.tcp_nodelay)?;
        socket.connect_timeout(&address.into(), timeout)?;
        Ok(socket.into())
    }

    fn client_config(&self) -> Result<ClientConfig, Error> {
        if self.timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timeout must be greater than zero",
            )
            .into());
        }
        let mut roots = RootCertStore::empty();
        if self.verify_peer {
            if let Some(path) = &self.ca_file {
                let pem = fs::read(path)?;
                for certificate in CertificateDer::pem_slice_iter(&pem) {
                    roots.add(certificate?)?;
                }
            } else {
                let native = rustls_native_certs::load_native_certs();
                roots.add_parsable_certificates(native.certs);
                if roots.is_empty() {
                    return Err(Error::NoTrustedRoots(format!("{:?}", native.errors)));
                }
            }
            if roots.is_empty() {
                return Err(Error::NoTrustedRoots("empty CA bundle".to_owned()));
            }
        }
        let provider = Arc::new(ring::default_provider());
        let builder =
            ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions()?;
        let mut config = if self.verify_peer && self.verify_peer_name {
            builder.with_root_certificates(roots).with_no_client_auth()
        } else {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SelectiveVerifier {
                    roots,
                    verify_peer: self.verify_peer,
                    verify_peer_name: self.verify_peer_name,
                }))
                .with_no_client_auth()
        };
        config.enable_sni = self.enable_sni;
        Ok(config)
    }
}

fn remaining(start: Instant, timeout: Duration) -> io::Result<Duration> {
    timeout
        .checked_sub(start.elapsed())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "certificate download timed out"))
}

struct DeadlineStream {
    stream: TcpStream,
    start: Instant,
    timeout: Duration,
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(remaining(self.start, self.timeout)?))?;
        self.stream.read(buffer)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(remaining(self.start, self.timeout)?))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[derive(Debug)]
struct SelectiveVerifier {
    roots: RootCertStore,
    verify_peer: bool,
    verify_peer_name: bool,
}

impl ServerCertVerifier for SelectiveVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let parsed = ParsedCertificate::try_from(end_entity)?;
        if self.verify_peer {
            verify_server_cert_signed_by_trust_anchor(
                &parsed,
                &self.roots,
                intermediates,
                now,
                ring::default_provider()
                    .signature_verification_algorithms
                    .all,
            )?;
        }
        if self.verify_peer_name {
            verify_server_name(&parsed, server_name)?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

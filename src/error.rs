use std::io;

/// An error reading, parsing, or downloading a certificate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The URL or host name is invalid.
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    /// The supplied IP address is invalid.
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(#[from] std::net::AddrParseError),
    /// Resolving the host failed or returned no addresses.
    #[error("Could not resolve host {0}")]
    HostDoesNotExist(String),
    /// A file or network operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// TLS verification or negotiation failed.
    #[error(transparent)]
    Tls(#[from] rustls::Error),
    /// PEM certificate data is malformed.
    #[error(transparent)]
    Pem(#[from] rustls::pki_types::pem::Error),
    /// No certificate was supplied by the peer or PEM file.
    #[error("No certificate installed or supplied")]
    NoCertificate,
    /// Certificate data is malformed or unsupported.
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),
    /// The selected trust store contains no usable certificates.
    #[error("No trusted root certificates: {0}")]
    NoTrustedRoots(String),
}

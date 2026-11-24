use std::{collections::BTreeMap, fmt, fs, net::IpAddr, path::Path};

use base64::{Engine, engine::general_purpose::STANDARD};
use md5::Md5;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_parser::{
    extensions::GeneralName, parse_x509_certificate, prelude::X509Name, public_key::PublicKey,
};

use crate::{Downloader, Error, Url};

/// An X.509 extension, including its original DER value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Extension {
    /// The extension's dotted object identifier.
    pub oid: String,
    /// Whether an unrecognized extension must cause verification to fail.
    pub critical: bool,
    /// The extension value, without its OCTET STRING wrapper.
    pub value: Vec<u8>,
}

/// Parsed certificate metadata. Names use dotted attribute OIDs as map keys.
///
/// This is native X.509 metadata, not OpenSSL's PHP-specific array format.
/// Every extension is retained, including ones this crate does not interpret.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CertificateFields {
    /// Subject distinguished name attributes, preserving repeated values.
    pub subject: BTreeMap<String, Vec<String>>,
    /// Issuer distinguished name attributes, preserving repeated values.
    pub issuer: BTreeMap<String, Vec<String>>,
    /// Decimal serial number.
    pub serial_number: String,
    /// Hexadecimal serial number, retaining leading zero bytes.
    pub serial_number_hex: String,
    /// Zero-based X.509 version (2 means v3).
    pub version: u32,
    /// Start of validity in UTC, serialized as Unix seconds.
    #[serde(with = "time::serde::timestamp")]
    pub valid_from: OffsetDateTime,
    /// End of validity in UTC, serialized as Unix seconds.
    #[serde(with = "time::serde::timestamp")]
    pub valid_to: OffsetDateTime,
    /// Signature algorithm object identifier.
    pub signature_algorithm_oid: String,
    /// Public key algorithm object identifier.
    pub public_key_algorithm_oid: String,
    /// Original subject public key info DER, including algorithm parameters.
    pub public_key_der: Vec<u8>,
    /// All certificate extensions in certificate order.
    pub extensions: Vec<Extension>,
}

/// Lossless, serializable certificate properties.
///
/// Reconstructing a certificate parses `der` again rather than trusting cached
/// metadata. This format is not PHP's serialized object or OpenSSL array format.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CertificateProperties {
    /// The complete DER-encoded certificate.
    pub der: Vec<u8>,
    /// The peer socket address, when downloaded.
    pub remote_address: Option<std::net::SocketAddr>,
}

/// An SSL certificate loaded from a host, file, PEM string, or DER bytes.
///
/// Loading a file does not verify trust. [`Self::is_valid`] checks dates and
/// optional domain coverage only. Downloads verify the chain and peer name
/// unless explicitly disabled on [`Downloader`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "CertificateProperties", into = "CertificateProperties")]
pub struct SslCertificate {
    der: Vec<u8>,
    fields: CertificateFields,
    domain: String,
    additional_domains: Vec<String>,
    public_key_algorithm: String,
    public_key_size: usize,
    signature_algorithm: String,
    remote_address: Option<std::net::SocketAddr>,
}

impl SslCertificate {
    /// Starts a certificate download with verification enabled.
    pub fn download() -> Downloader {
        Downloader::new()
    }

    /// Downloads a host's leaf certificate with verification enabled.
    ///
    /// # Errors
    /// Returns an error for invalid hosts, network failures, or invalid TLS peers.
    pub fn create_for_host_name(host: &str) -> Result<Self, Error> {
        Self::download().for_host(host)
    }

    /// Loads the first certificate in a PEM file, or a single DER certificate.
    ///
    /// # Errors
    /// Returns an error if reading or parsing the certificate fails.
    pub fn create_from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let bytes = fs::read(path)?;
        if bytes
            .windows(27)
            .any(|part| part == b"-----BEGIN CERTIFICATE-----")
        {
            Self::create_from_string(
                &String::from_utf8(bytes).map_err(|e| Error::InvalidCertificate(e.to_string()))?,
            )
        } else {
            Self::from_der(&bytes)
        }
    }

    /// Loads the first certificate from a PEM string.
    ///
    /// # Errors
    /// Returns an error for missing or malformed certificate data.
    pub fn create_from_string(pem: &str) -> Result<Self, Error> {
        let der = CertificateDer::pem_slice_iter(pem.as_bytes())
            .next()
            .ok_or(Error::NoCertificate)??;
        Self::from_der(der.as_ref())
    }

    /// Parses a single DER certificate, rejecting trailing data.
    ///
    /// # Errors
    /// Returns an error if the DER or its public key is malformed.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let (remaining, cert) =
            parse_x509_certificate(der).map_err(|e| Error::InvalidCertificate(e.to_string()))?;
        if !remaining.is_empty() {
            return Err(Error::InvalidCertificate("trailing DER data".to_owned()));
        }
        let name = |name: &X509Name<'_>| {
            let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for attr in name.iter_attributes() {
                let value = attr
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|_| STANDARD.encode(attr.as_slice()));
                fields
                    .entry(attr.attr_type().to_id_string())
                    .or_default()
                    .push(value);
            }
            fields
        };
        let subject = name(cert.subject());
        let domain = first_attribute(&subject, "2.5.4.3").to_owned();
        let mut additional_domains = Vec::new();
        if let Some(san) = cert
            .subject_alternative_name()
            .map_err(|e| Error::InvalidCertificate(e.to_string()))?
        {
            for entry in &san.value.general_names {
                match entry {
                    GeneralName::DNSName(dns) => additional_domains.push((*dns).to_owned()),
                    GeneralName::IPAddress(bytes) => {
                        let ip = match bytes.len() {
                            4 => IpAddr::from(
                                <[u8; 4]>::try_from(*bytes)
                                    .map_err(|e| Error::InvalidCertificate(e.to_string()))?,
                            ),
                            16 => IpAddr::from(
                                <[u8; 16]>::try_from(*bytes)
                                    .map_err(|e| Error::InvalidCertificate(e.to_string()))?,
                            ),
                            _ => {
                                return Err(Error::InvalidCertificate(
                                    "invalid IP subject alternative name".to_owned(),
                                ));
                            }
                        };
                        additional_domains.push(format!("IP Address:{ip}"));
                    }
                    GeneralName::RFC822Name(email) => {
                        additional_domains.push(format!("email:{email}"))
                    }
                    GeneralName::URI(uri) => additional_domains.push(format!("URI:{uri}")),
                    _ => {}
                }
            }
        }
        let key = cert
            .public_key()
            .parsed()
            .map_err(|e| Error::InvalidCertificate(e.to_string()))?;
        let key_oid = cert.public_key().algorithm.algorithm.to_id_string();
        let public_key_algorithm = match key {
            PublicKey::RSA(_) => "RSA",
            PublicKey::EC(_) => "EC",
            PublicKey::DSA(_) => "DSA",
            _ if key_oid == "1.3.101.112" => "Ed25519",
            _ if key_oid == "1.3.101.113" => "Ed448",
            _ if key_oid == "1.2.840.113549.1.3.1" || key_oid == "1.2.840.10046.2.1" => "DH",
            _ => "Unknown",
        }
        .to_owned();
        let public_key_size = match &key {
            PublicKey::RSA(rsa) => num_bigint::BigUint::from_bytes_be(rsa.modulus).bits() as usize,
            PublicKey::EC(point) => match cert
                .public_key()
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|oid| oid.to_id_string())
                .as_deref()
            {
                Some("1.2.840.10045.3.1.7" | "1.3.132.0.10") => 256,
                Some("1.3.132.0.34") => 384,
                Some("1.3.132.0.35") => 521,
                _ => point.key_size(),
            },
            _ if public_key_algorithm == "Ed25519" => 256,
            _ if public_key_algorithm == "Ed448" => 456,
            _ if matches!(public_key_algorithm.as_str(), "DSA" | "DH") => {
                if let Some(parameters) = &cert.public_key().algorithm.parameters {
                    let (_, prime) =
                        x509_parser::der_parser::der::parse_der_integer(parameters.data)
                            .map_err(|e| Error::InvalidCertificate(e.to_string()))?;
                    let bytes = prime
                        .as_slice()
                        .map_err(|e| Error::InvalidCertificate(e.to_string()))?;
                    num_bigint::BigUint::from_bytes_be(bytes).bits() as usize
                } else {
                    0
                }
            }
            _ => key.key_size(),
        };
        let signature_oid = cert.signature_algorithm.algorithm.to_id_string();
        let signature_algorithm = signature_name(&signature_oid).to_owned();
        Ok(Self {
            der: der.to_vec(),
            fields: CertificateFields {
                subject,
                issuer: name(cert.issuer()),
                serial_number: num_bigint::BigUint::from_bytes_be(cert.raw_serial()).to_string(),
                serial_number_hex: cert
                    .raw_serial()
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect(),
                version: cert.version().0,
                valid_from: cert.validity().not_before.to_datetime(),
                valid_to: cert.validity().not_after.to_datetime(),
                signature_algorithm_oid: signature_oid,
                public_key_algorithm_oid: key_oid,
                public_key_der: cert.public_key().raw.to_vec(),
                extensions: cert
                    .extensions()
                    .iter()
                    .map(|ext| Extension {
                        oid: ext.oid.to_id_string(),
                        critical: ext.critical,
                        value: ext.value.to_vec(),
                    })
                    .collect(),
            },
            domain,
            additional_domains,
            public_key_algorithm,
            public_key_size,
            signature_algorithm,
            remote_address: None,
        })
    }

    /// Reconstructs a certificate from lossless properties.
    ///
    /// # Errors
    /// Returns an error if the stored DER certificate is invalid.
    pub fn create_from_array(properties: CertificateProperties) -> Result<Self, Error> {
        Self::try_from(properties)
    }

    /// Returns lossless properties for storage or Serde serialization.
    #[must_use]
    pub fn to_array(&self) -> CertificateProperties {
        CertificateProperties {
            der: self.der.clone(),
            remote_address: self.remote_address,
        }
    }

    /// Returns the original DER certificate.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// Returns the certificate in PEM format.
    #[must_use]
    pub fn to_pem(&self) -> String {
        Self::der2pem(&self.der)
    }

    /// Wraps DER bytes in a PEM certificate envelope, with 64-column base64.
    #[must_use]
    pub fn der2pem(der: &[u8]) -> String {
        let encoded = STANDARD.encode(der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            for byte in line {
                pem.push(char::from(*byte));
            }
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }

    /// Returns the parsed X.509 metadata, including all raw extensions.
    #[must_use]
    pub fn raw_certificate_fields(&self) -> &CertificateFields {
        &self.fields
    }

    /// Returns the metadata as JSON. Its shape is Rust-native, not OpenSSL's.
    #[must_use]
    pub fn raw_certificate_fields_json(&self) -> String {
        // CertificateFields contains only JSON-compatible strings, integers and vectors.
        serde_json::json!(self.fields).to_string()
    }

    /// Returns an MD5 identifier of the metadata JSON, not a security digest.
    #[must_use]
    pub fn hash(&self) -> String {
        format!("{:x}", Md5::digest(self.raw_certificate_fields_json()))
    }

    /// Returns the issuer common name, or an empty string when absent.
    #[must_use]
    pub fn issuer(&self) -> &str {
        first_attribute(&self.fields.issuer, "2.5.4.3")
    }

    /// Returns the decimal serial number.
    #[must_use]
    pub fn serial_number(&self) -> &str {
        &self.fields.serial_number
    }

    /// Returns the first subject common name, or an empty string when absent.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the signature algorithm name, or its dotted OID if unknown.
    #[must_use]
    pub fn signature_algorithm(&self) -> &str {
        &self.signature_algorithm
    }

    /// Returns the issuer organization, or an empty string when absent.
    #[must_use]
    pub fn organization(&self) -> &str {
        first_attribute(&self.fields.issuer, "2.5.4.10")
    }

    /// Returns the subject organization, or an empty string when absent.
    #[must_use]
    pub fn subject_organization(&self) -> &str {
        first_attribute(&self.fields.subject, "2.5.4.10")
    }

    /// Returns the lowercase, unseparated SHA-1 fingerprint. Not for authentication.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        format!("{:x}", Sha1::digest(&self.der))
    }

    /// Returns the lowercase, unseparated SHA-256 fingerprint.
    #[must_use]
    pub fn fingerprint_sha256(&self) -> String {
        format!("{:x}", Sha256::digest(&self.der))
    }

    /// Returns subject alternative names in certificate order.
    ///
    /// DNS names are unprefixed; IP addresses use `IP Address:`, emails use
    /// `email:`, and URIs use `URI:`. Non-host entries never match URLs.
    #[must_use]
    pub fn additional_domains(&self) -> &[String] {
        &self.additional_domains
    }

    /// Returns unique alternative names followed by the subject common name.
    #[must_use]
    pub fn domains(&self) -> Vec<String> {
        let mut domains = Vec::new();
        for domain in self
            .additional_domains
            .iter()
            .map(String::as_str)
            .chain([self.domain()])
        {
            if !domain.is_empty() && !domains.iter().any(|d| d == domain) {
                domains.push(domain.to_owned());
            }
        }
        domains
    }

    /// Returns the public key algorithm name, or `Unknown`.
    #[must_use]
    pub fn public_key_algorithm(&self) -> &str {
        &self.public_key_algorithm
    }

    /// Returns the public key size in bits.
    #[must_use]
    pub fn public_key_size(&self) -> usize {
        self.public_key_size
    }

    /// Returns the UTC date when the certificate becomes valid.
    #[must_use]
    pub fn valid_from_date(&self) -> OffsetDateTime {
        self.fields.valid_from
    }

    /// Returns the UTC expiration date.
    #[must_use]
    pub fn expiration_date(&self) -> OffsetDateTime {
        self.fields.valid_to
    }

    /// Returns whole days between the start and end of validity.
    #[must_use]
    pub fn lifespan_in_days(&self) -> i64 {
        (self.expiration_date() - self.valid_from_date()).whole_days()
    }

    /// Returns whether the certificate has expired at the current time.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(OffsetDateTime::now_utc())
    }

    /// Returns whether expiration is strictly before `now`.
    #[must_use]
    pub fn is_expired_at(&self, now: OffsetDateTime) -> bool {
        self.expiration_date() < now
    }

    /// Checks current dates and optionally domain coverage, not chain trust.
    #[must_use]
    pub fn is_valid(&self, url: Option<&str>) -> bool {
        self.is_valid_at(OffsetDateTime::now_utc(), url)
    }

    /// Checks inclusive validity boundaries and optional domain coverage at `now`.
    #[must_use]
    pub fn is_valid_at(&self, now: OffsetDateTime, url: Option<&str>) -> bool {
        now >= self.valid_from_date()
            && now <= self.expiration_date()
            && url
                .filter(|u| !u.is_empty())
                .is_none_or(|u| self.applies_to_url(u))
    }

    /// Checks that the certificate is currently valid and expires after `date`.
    #[must_use]
    pub fn is_valid_until(&self, date: OffsetDateTime, url: Option<&str>) -> bool {
        self.expiration_date() > date && self.is_valid(url)
    }

    /// Returns signed whole days from now to expiration, truncating toward zero.
    #[must_use]
    pub fn days_until_expiration_date(&self) -> i64 {
        self.days_until_expiration_date_at(OffsetDateTime::now_utc())
    }

    /// Returns signed whole days from `now` to expiration, truncating toward zero.
    #[must_use]
    pub fn days_until_expiration_date_at(&self, now: OffsetDateTime) -> i64 {
        (self.expiration_date() - now).whole_days()
    }

    /// Checks URL or IP coverage, including single-label wildcard domains.
    ///
    /// This is a metadata query, not TLS name verification. It includes the
    /// common name even when SANs exist; the TLS downloader follows WebPKI rules.
    /// Malformed URLs return false.
    #[must_use]
    pub fn applies_to_url(&self, input: &str) -> bool {
        let host = match input.parse::<IpAddr>() {
            Ok(ip) => ip.to_string(),
            Err(_) => match Url::new(input) {
                Ok(url) => url.host_name().to_owned(),
                Err(_) => return false,
            },
        };
        self.domains().iter().any(|domain| {
            let domain = domain.to_ascii_lowercase();
            let domain = domain.strip_prefix("ip address:").unwrap_or(&domain);
            if let Ok(ip) = domain.parse::<IpAddr>() {
                return host.parse::<IpAddr>().is_ok_and(|host| host == ip);
            }
            if domain.contains(':') || domain.contains('@') {
                return false;
            }
            if host == domain {
                return true;
            }
            domain.strip_prefix("*.").is_some_and(|suffix| {
                host.strip_suffix(suffix).is_some_and(|prefix| {
                    prefix.ends_with('.')
                        && prefix.len() > 1
                        && !prefix[..prefix.len() - 1].contains('.')
                })
            })
        })
    }

    /// Checks literal domain membership, also accepting subdomains of an entry.
    ///
    /// Unlike [`Self::applies_to_url`], this preserves case and treats `*` literally.
    #[must_use]
    pub fn contains_domain(&self, domain: &str) -> bool {
        self.domains()
            .iter()
            .any(|entry| domain == entry || domain.ends_with(&format!(".{entry}")))
    }

    /// Compares the issuer and subject common names, as in the PHP package.
    ///
    /// This is a heuristic, not cryptographic signature or trust verification.
    #[must_use]
    pub fn is_self_signed(&self) -> bool {
        self.issuer() == self.domain()
    }

    /// Returns whether the certificate uses a SHA-1 signature algorithm.
    #[must_use]
    pub fn uses_sha1_hash(&self) -> bool {
        matches!(
            self.fields.signature_algorithm_oid.as_str(),
            "1.2.840.113549.1.1.5" | "1.2.840.10045.4.1" | "1.2.840.10040.4.3" | "1.3.14.3.2.29"
        )
    }

    /// Returns whether the certificate has the CT precertificate poison extension.
    #[must_use]
    pub fn is_pre_certificate(&self) -> bool {
        self.fields
            .extensions
            .iter()
            .any(|ext| ext.oid == "1.3.6.1.4.1.11129.2.4.3")
    }

    /// Returns the peer socket address, or `None` for a locally loaded certificate.
    #[must_use]
    pub fn remote_address(&self) -> Option<std::net::SocketAddr> {
        self.remote_address
    }

    pub(crate) fn set_remote_address(&mut self, address: std::net::SocketAddr) {
        self.remote_address = Some(address);
    }
}

impl TryFrom<CertificateProperties> for SslCertificate {
    type Error = Error;

    fn try_from(properties: CertificateProperties) -> Result<Self, Self::Error> {
        let mut certificate = Self::from_der(&properties.der)?;
        certificate.remote_address = properties.remote_address;
        Ok(certificate)
    }
}

impl From<SslCertificate> for CertificateProperties {
    fn from(certificate: SslCertificate) -> Self {
        Self {
            der: certificate.der,
            remote_address: certificate.remote_address,
        }
    }
}

impl fmt::Display for SslCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.raw_certificate_fields_json())
    }
}

fn first_attribute<'a>(name: &'a BTreeMap<String, Vec<String>>, oid: &str) -> &'a str {
    name.get(oid)
        .and_then(|values| values.first())
        .map_or("", String::as_str)
}

fn signature_name(oid: &str) -> &str {
    match oid {
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => "RSA-SHA1",
        "1.2.840.113549.1.1.11" => "RSA-SHA256",
        "1.2.840.113549.1.1.12" => "RSA-SHA384",
        "1.2.840.113549.1.1.13" => "RSA-SHA512",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.2.840.10040.4.3" => "DSA-SHA1",
        "1.3.101.112" => "ED25519",
        "1.3.101.113" => "ED448",
        _ => oid,
    }
}

---
title: Usage
weight: 4
---

You can create an instance of `SslCertificate` with this named constructor:

```rust,no_run
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
let certificate = SslCertificate::create_for_host_name("spatie.be")?;
# Ok(())
# }
```

You can create an instance of `SslCertificate` passing the port with this named constructor:

```rust,no_run
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
let certificate = SslCertificate::create_for_host_name("spatie.be:443")?;
# Ok(())
# }
```

You can use this fluent style to specify a specific port to connect to.

```rust,no_run
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let custom_port = 443;
# let host_name = "spatie.be";
SslCertificate::download()
    .using_port(custom_port)
    .for_host(host_name)?;
# Ok(())
# }
```

You can check the certificate on a different IP address using the same style.

```rust,no_run
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let ip_address = "127.0.0.1";
# let host_name = "spatie.be";
SslCertificate::download()
    .from_ip_address(ip_address)?
    .for_host(host_name)?;
# Ok(())
# }
```

This also works with IPv6 addresses.

```rust,no_run
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
SslCertificate::download()
    .from_ip_address("2a00:1450:4001:80e::200e")?
    .for_host("google.com")?;
# Ok(())
# }
```

You can specify socket context options using the typed `SocketOptions` struct.

```rust,no_run
# use spatie_ssl_certificate::{SslCertificate, SocketOptions};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let host_name = "spatie.be";
SslCertificate::download()
    .with_socket_context_options(SocketOptions {
        bind_address: Some("0.0.0.0:0".parse()?),
        ..SocketOptions::default()
    })
    .for_host(host_name)?;
# Ok(())
# }
```

By default the peer is verified against the CA bundle of your system. You can verify it against your own bundle of trusted root certificates instead.

```rust,no_run
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let host_name = "spatie.be";
SslCertificate::download()
    .with_ca_file("/path/to/cacert.pem")
    .for_host(host_name)?;
# Ok(())
# }
```

If the given `ip_address` is invalid, `Error::InvalidIpAddress` is returned.

If the given `host_name` is invalid, `Error::InvalidUrl` is returned.

If the given `host_name` is valid but there was a problem downloading the certificate, an `Error` describes the DNS, I/O or TLS failure. No certificate is represented by `Error::NoCertificate`, not a boolean.

### Getting the issuer name

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/spatieCertificate.pem")))?;
certificate.issuer(); // returns "Let's Encrypt Authority X3"
# assert_eq!(certificate.issuer(), "Let's Encrypt Authority X3");
# Ok(())
# }
```

### Getting the domain name

Returns the primary domain name for the certificate.

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/documentation.pem")))?;
certificate.domain(); // returns "spatie.be"
# assert_eq!(certificate.domain(), "spatie.be");
# Ok(())
# }
```

### Getting the certificate's signing algorithm

Returns the algorithm used for signing the certificate.

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/spatieCertificate.pem")))?;
certificate.signature_algorithm(); // returns "RSA-SHA256"
# assert_eq!(certificate.signature_algorithm(), "RSA-SHA256");
# Ok(())
# }
```

### Getting the certificate's organization

Returns the organization belonging to the certificate.

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/documentation.pem")))?;
certificate.organization(); // returns "Spatie BVBA"
# assert_eq!(certificate.organization(), "Spatie BVBA");
# Ok(())
# }
```

### Getting the subject's organization

Returns the organization of the certificate's subject.

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/documentation.pem")))?;
certificate.subject_organization(); // returns "Spatie BVBA"
# assert_eq!(certificate.subject_organization(), "Spatie BVBA");
# Ok(())
# }
```

These getters return an empty string when the certificate has no corresponding common name or organization.

### Getting the additional domain names

A certificate can cover multiple (sub)domains. Here's how to get them.

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/documentation.pem")))?;
certificate.additional_domains(); // returns ["spatie.be", "www.spatie.be"]
# assert_eq!(certificate.additional_domains(), ["spatie.be", "www.spatie.be"]);
# Ok(())
# }
```

A domain name returned with this method can start with `*`, meaning it is valid for single-label subdomains of that domain. IP alternative names retain the `IP Address:` prefix. `domains()` combines the alternative names with the primary domain and removes duplicates.

### Getting the fingerprint

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/spatieCertificate.pem")))?;
certificate.fingerprint(); // returns a fingerprint for the certificate
# Ok(())
# }
```

This is the lowercase SHA-1 digest of the DER certificate, without separators. Use SHA-256 for security-sensitive comparisons.

### Getting the SHA256 fingerprint

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/spatieCertificate.pem")))?;
certificate.fingerprint_sha256(); // returns a SHA256 fingerprint for the certificate
# Ok(())
# }
```

### Getting the date when the certificate becomes valid

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/spatieCertificate.pem")))?;
certificate.valid_from_date(); // returns an OffsetDateTime
# Ok(())
# }
```

### Getting the expiration date

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/spatieCertificate.pem")))?;
certificate.expiration_date(); // returns an OffsetDateTime
# Ok(())
# }
```

Dates use UTC. `days_until_expiration_date()` returns signed whole days, truncating toward zero. `lifespan_in_days()` returns the whole days between the validity dates.

### Determining if the certificate is still valid

Returns true if the current date and time is between `valid_from_date` and `expiration_date`, including the boundaries.

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/spatieCertificate.pem")))?;
certificate.is_valid(None); // returns a boolean
# Ok(())
# }
```

You also use this method to determine if a given domain is covered by the certificate. Of course it'll keep checking if the current date and time is between `valid_from_date` and `expiration_date`.

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/documentation.pem")))?;
certificate.is_valid(Some("spatie.be")); // returns true
certificate.is_valid(Some("laravel.com")); // returns false
# assert!(certificate.is_valid(Some("spatie.be")));
# assert!(!certificate.is_valid(Some("laravel.com")));
# Ok(())
# }
```

This is a metadata check, not a check of the certificate's chain of trust. Downloads verify trust separately. `applies_to_url()` checks domain coverage without checking dates. It accepts URLs, bare host names and IP addresses. It checks the primary domain as well as alternative names, just like the PHP package. rustls uses stricter WebPKI rules for the actual TLS handshake.

### Determining if the certificate is still valid until a given date

Returns true if the certificate is valid and if the `expiration_date` is after the given date.

```rust
# use spatie_ssl_certificate::SslCertificate;
# use time::{Duration, OffsetDateTime};
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/spatieCertificate.pem")))?;
certificate.is_valid_until(OffsetDateTime::now_utc() + Duration::days(7), None); // returns a boolean
# Ok(())
# }
```

For deterministic date checks, use `is_valid_at(now, url)`, `is_expired_at(now)` and `days_until_expiration_date_at(now)` instead of changing a global clock.

### Determining if the certificate is expired

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/spatieCertificate.pem")))?;
certificate.is_expired(); // returns a boolean if expired
# assert!(certificate.is_expired());
# Ok(())
# }
```

### Convert the certificate to an array

You can convert a certificate to a `CertificateProperties` struct using the `to_array` method.

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/spatieCertificate.pem")))?;
let certificate_properties = certificate.to_array();
# Ok(())
# }
```

The properties can be used to create a new instance of the certificate.

```rust
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let certificate = SslCertificate::create_from_string(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/spatieCertificate.pem")))?;
# let certificate_properties = certificate.to_array();
SslCertificate::create_from_array(certificate_properties)?;
# Ok(())
# }
```

`CertificateProperties` stores DER bytes and the optional peer socket address. Both the properties and `SslCertificate` implement Serde serialization. Deserialization parses the DER again. These are Rust-native properties, not PHP's array or serialized object format.

### Other certificate properties

`serial_number()` returns the serial number as a decimal string. `public_key_algorithm()` and `public_key_size()` return the public key algorithm and size in bits.

`raw_certificate_fields()` exposes typed metadata, with distinguished-name attributes keyed by dotted OIDs and every extension's original DER value. `raw_certificate_fields_json()` and the certificate's `Display` implementation return that metadata as JSON. `hash()` is an MD5 identifier of this JSON, not a security digest. Its value differs from PHP's OpenSSL-specific metadata hash; use a fingerprint to compare the same certificate across languages.

`contains_domain()` checks literal domain membership, including subdomains of an entry. It is case-sensitive and treats `*` literally. Use `applies_to_url()` for case-insensitive wildcard and URL matching.

`is_self_signed()` compares the issuer and subject common names, just like the PHP package. It is a heuristic, not signature or trust verification. `uses_sha1_hash()` detects SHA-1 certificate signatures. `is_pre_certificate()` checks for the CT poison extension.

`remote_address()` returns the peer's `SocketAddr` when downloaded, or `None` when loaded locally. `as_der()` and `to_pem()` expose the original certificate. `SslCertificate::der2pem()` wraps DER bytes in a PEM envelope.

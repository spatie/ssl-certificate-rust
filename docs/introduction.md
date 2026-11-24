---
title: Introduction
weight: 1
---

The class provided by this package makes it incredibly easy to query the properties on an SSL certificate. We have three options for fetching a certificate. Here's an example:

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let path_to_certificate_file = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/spatieCertificate.pem");
# let certificate_data = std::fs::read_to_string(path_to_certificate_file)?;
use spatie_ssl_certificate::SslCertificate;

// fetch the certificate using a URL
let certificate = SslCertificate::create_for_host_name("spatie.be")?;

// or from a certificate file
let certificate = SslCertificate::create_from_file(path_to_certificate_file)?;

// or from a string
let certificate = SslCertificate::create_from_string(&certificate_data)?;

certificate.is_valid(None); // returns true if the certificate is currently valid

certificate.expiration_date(); // returns an OffsetDateTime
certificate.valid_from_date(); // returns an OffsetDateTime

certificate.days_until_expiration_date(); // returns the days between today and expiration_date
certificate.lifespan_in_days(); // returns the days between valid_from_date and expiration_date

certificate.issuer(); // returns "Let's Encrypt Authority X3"
certificate.organization(); // returns the organization name when available
certificate.subject_organization(); // returns the subject organization name when available
certificate.public_key_algorithm(); // returns the public key algorithm
certificate.public_key_size(); // returns the public key size
certificate.signature_algorithm(); // returns the signature algorithm
# Ok(())
# }
```

This is the Rust version of [spatie/ssl-certificate](https://github.com/spatie/ssl-certificate).

## Downloading invalid certificates

If you want to download certificates even if they are invalid (for example, if they are expired), you can turn off verification explicitly:

```rust,no_run
# use spatie_ssl_certificate::{Downloader, SslCertificate};
# use std::time::Duration;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
# let timeout_in_seconds = 30;
let certificate = Downloader::download_certificate_from_url(
    "expired.badssl.com",
    Duration::from_secs(timeout_in_seconds),
    false,
)?;
# Ok(())
# }
```

This disables both chain and peer name verification. Use it only to inspect a certificate, never to authenticate a server. Handshake signatures are still checked by rustls.

Continue with [installation](installation-and-setup.md) and [usage](usage.md).

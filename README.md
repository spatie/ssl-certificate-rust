# spatie-ssl-certificate

[![Latest version on crates.io](https://img.shields.io/crates/v/spatie-ssl-certificate.svg?style=flat-square)](https://crates.io/crates/spatie-ssl-certificate)
[![Tests](https://img.shields.io/github/actions/workflow/status/spatie/ssl-certificate-rust/ci.yml?branch=main&style=flat-square)](https://github.com/spatie/ssl-certificate-rust/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://github.com/spatie/ssl-certificate-rust/blob/main/LICENSE.md)
[![Total downloads](https://img.shields.io/crates/d/spatie-ssl-certificate.svg?style=flat-square)](https://crates.io/crates/spatie-ssl-certificate)

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

This is the Rust version of [spatie/ssl-certificate](https://github.com/spatie/ssl-certificate). It uses rustls for TLS and x509-parser for certificate metadata.

## Support us

[<img src="https://spatie.be/github-ad-image/spatie-ssl-certificate.jpg" alt="Support Spatie's open source work" width="419px" />](https://spatie.be/github-ad-click/spatie-ssl-certificate)

We invest a lot of resources into creating [best in class open source packages](https://spatie.be/open-source). You can support us by [buying one of our paid products](https://spatie.be/open-source/support-us).

We highly appreciate you sending us a postcard from your hometown, mentioning which of our package(s) you are using. You'll find our address on [our contact page](https://spatie.be/about-us). We publish all received postcards on [our virtual postcard wall](https://spatie.be/open-source/postcards).

## Installation

Requires Rust 1.89 or newer. The crate is not yet published to crates.io. Add this Git dependency to your `Cargo.toml`:

```toml
[dependencies]
spatie-ssl-certificate = { git = "https://github.com/spatie/ssl-certificate-rust", branch = "main" }
```

Commit your application's `Cargo.lock` to keep the selected Git revision between builds.

## Usage

You can create an instance of `SslCertificate` with this named constructor:

```rust,no_run
# use spatie_ssl_certificate::SslCertificate;
# fn main() -> Result<(), spatie_ssl_certificate::Error> {
let certificate = SslCertificate::create_for_host_name("spatie.be")?;
# Ok(())
# }
```

See the [usage guide](docs/usage.md) for ports, IP addresses, certificate properties and validity checks, and [downloading certificates](docs/downloading-certificates.md) for chain downloads and TLS options. The [v1 documentation](https://spatie.be/docs/ssl-certificate-rust/v1/introduction) follows the PHP package's examples.

Downloads verify the certificate chain and host name against the system CA bundle by default. `is_valid` checks dates and optional domain coverage only; it does not establish trust for a certificate loaded from a file or string.

## Testing

```sh
cargo test --locked --all-targets --all-features
cargo test --locked --doc --all-features
```

See [all quality checks](https://github.com/spatie/ssl-certificate-rust/blob/main/docs/testing.md). The README and Markdown guides are tested by rustdoc, including setup on hidden `# ` lines.

Tests use local TLS servers and certificate fixtures. They do not depend on public hosts being reachable. Network examples compile without contacting those hosts.

## Changelog

See [CHANGELOG.md](https://github.com/spatie/ssl-certificate-rust/blob/main/CHANGELOG.md).

## Contributing

See [CONTRIBUTING.md](https://github.com/spatie/ssl-certificate-rust/blob/main/CONTRIBUTING.md) and the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).

Using an AI coding agent? Load Apollo's [rust-best-practices skill](https://github.com/apollographql/skills/tree/main/skills/rust-best-practices) when writing or reviewing code in this package.

## Security Vulnerabilities

Report vulnerabilities privately using the instructions in [SECURITY.md](https://github.com/spatie/ssl-certificate-rust/blob/main/SECURITY.md).

## Credits

- [Spatie](https://github.com/freekmurze)
- [All contributors](https://github.com/spatie/ssl-certificate-rust/graphs/contributors)

## License

The MIT License (MIT). See [LICENSE.md](https://github.com/spatie/ssl-certificate-rust/blob/main/LICENSE.md).

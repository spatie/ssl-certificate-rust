---
title: Downloading certificates
weight: 5
---

## Downloading invalid certificates

If you want to download certificates even if they are invalid (for example, if they are expired), you can turn off verification explicitly:

```rust,no_run
# use spatie_ssl_certificate::Downloader;
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

This disables chain and peer name verification. Only do this to inspect an invalid certificate, never to authenticate a server.

The fluent downloader lets you disable chain verification with `with_verify_peer(false)` and peer name verification with `with_verify_peer_name(false)` independently. Disabling either weakens authentication. Handshake signatures are always checked by rustls, even when both checks are disabled.

## Using your own CA bundle

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

This replaces the system roots. An unreadable, empty or malformed CA bundle fails instead of silently disabling verification. The downloader does not fetch missing intermediates or check revocation through OCSP or CRLs.

## Downloading the full chain

Use `with_full_chain(true).get_certificates(host_name)` to get all certificates sent by the server. The leaf comes first and duplicate certificates are removed. Without that option, only the leaf is returned. `for_host()` always returns the leaf.

The result contains the chain the server sent, not the local trust store. Servers normally omit the root certificate.

## Timeouts and SNI

`set_timeout(Duration::from_secs(30))` sets the timeout for TCP connection attempts and the TLS handshake together. The default is 30 seconds. A zero timeout is rejected. DNS uses the operating system's synchronous resolver and is not covered by this timeout.

SNI is enabled by default. `using_sni(false)` turns it off without disabling hostname verification. `from_ip_address()` changes the connection target, but the original host name is still used for SNI and verification. An explicit port in the URL takes precedence over `using_port()`.

This package only performs a TLS handshake. It sends no HTTP request and never follows redirects, so there is no equivalent of PHP's ineffective `setFollowLocation` option.

## Socket context options

`with_socket_context_options()` accepts `SocketOptions`, not a PHP context array. Set `bind_address` for a local bind address and port, `ipv6_only` for `IPV6_V6ONLY`, `tcp_nodelay` for TCP_NODELAY or `reuse_address` for SO_REUSEADDR. The bind address family must match the connection target.

rustls negotiates TLS 1.2 or 1.3 with modern cipher suites. A server that only supports obsolete TLS versions or algorithms cannot be inspected through this downloader, even with verification disabled. You can still parse its certificate from a PEM file or DER bytes.

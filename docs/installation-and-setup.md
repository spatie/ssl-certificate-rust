---
title: Installation
weight: 3
---

Requires Rust 1.89 or newer. Install Rust using [rustup](https://rustup.rs/).

You can install the package via Cargo. Add this Git dependency to your `Cargo.toml`:

```toml
[dependencies]
spatie-ssl-certificate = { git = "https://github.com/spatie/ssl-certificate-rust", branch = "main" }
```

The crate is not yet published to crates.io. Commit your application's `Cargo.lock` to keep the selected Git revision between builds.

Downloads use your system's trusted CA certificates. On Linux, install your distribution's `ca-certificates` package if the trust store is empty. You can also [use your own CA bundle](downloading-certificates.md#using-your-own-ca-bundle).

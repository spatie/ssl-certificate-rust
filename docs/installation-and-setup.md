---
title: Installation
weight: 3
---

Requires Rust 1.89 or newer. Install Rust using [rustup](https://rustup.rs/).

You can install the package via Cargo. Add the crate to your `Cargo.toml`:

```toml
[dependencies]
spatie-ssl-certificate = "1"
```

Downloads use your system's trusted CA certificates. On Linux, install your distribution's `ca-certificates` package if the trust store is empty. You can also [use your own CA bundle](downloading-certificates.md).

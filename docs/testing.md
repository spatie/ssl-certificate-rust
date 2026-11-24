---
title: Testing
weight: 6
---

Run these checks from the package directory:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo test --locked --doc --all-features
cargo doc --locked --no-deps --all-features
cargo package --locked
```

Set `RUSTDOCFLAGS` to `-D warnings` when running the documentation commands. In POSIX shells, prefix each command with `RUSTDOCFLAGS='-D warnings'`. In PowerShell, first run `$env:RUSTDOCFLAGS = '-D warnings'`.

README.md and all Markdown pages in docs/ participate in rustdoc tests. Setup lines prefixed with `# ` compile and execute but are hidden in rendered rustdoc. Assertions check the examples' results. Network examples use `no_run`: they compile without contacting public hosts.

Integration tests run real TLS 1.2 and 1.3 servers on loopback, including IPv6. They cover trust, name checks, expiry, SNI, custom CA bundles, socket binding, chain capture and a trickling server's handshake deadline. The PEM and DER fixtures come from the PHP package. `documentation.pem` is a synthetic certificate with the PHP README's sample names; it is not a trusted certificate issued to Spatie.

Check the minimum supported Rust version:

```sh
rustup toolchain install 1.89.0 --profile minimal
cargo +1.89.0 test --locked --all-targets --all-features
cargo +1.89.0 test --locked --doc --all-features
```

Check security advisories:

```sh
cargo install cargo-audit --locked
cargo audit --deny warnings
```

CI runs stable checks on Linux, macOS and Windows, and the MSRV and audit checks on Linux. An audit requires access to the RustSec advisory database.

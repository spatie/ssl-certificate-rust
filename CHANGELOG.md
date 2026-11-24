# Changelog

All notable changes to `spatie-ssl-certificate` will be documented in this file.

## Unreleased

- Download leaf certificates and peer-supplied chains with TLS verification enabled by default.
- Read PEM and DER certificates, query names and algorithms, check dates and domains, and calculate fingerprints.
- Store certificates with Serde and restore them from validated DER properties.

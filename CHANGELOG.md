# Changelog

All notable changes to pqguard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-23

### Added
- ML-KEM-768 key generation (NIST FIPS 203)
- ML-KEM-768 encapsulate/decapsulate
- AES-256-GCM file encryption
- HKDF-SHA256 key derivation
- PQGR binary envelope format
- CLI with keygen, encrypt, decrypt, verify, info commands
- Cross-platform support (Linux, macOS, Windows)
- 6 integration tests
- CI/CD pipeline (fmt, clippy, test, security audit)
- Landing page

# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in pqguard, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Use [GitHub Security Advisories](https://github.com/BartoszOsiej/pqguard/security/advisories/new)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix**: Depends on severity, typically within 2 weeks

## Scope

The following are in scope:
- Cryptographic vulnerabilities in the encryption/decapsulation logic
- Key handling vulnerabilities
- Authentication bypass
- Memory safety issues

The following are out of scope:
- Denial of service
- Issues in dependencies (report upstream)

## Cryptographic Guarantees

pqguard uses:
- ML-KEM-768 (NIST FIPS 203) for key encapsulation
- AES-256-GCM (NIST SP 800-38D) for symmetric encryption
- HKDF-SHA256 (RFC 5869) for key derivation

These are NIST-standardized algorithms with formal security proofs.

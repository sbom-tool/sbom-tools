# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in sbom-tools, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **GitHub Private Vulnerability Reporting (preferred):** Use the [Security Advisories](https://github.com/sbom-tool/sbom-tools/security/advisories/new) page to privately report a vulnerability.
2. **Email:** Send details to the maintainers via the email listed in `Cargo.toml`.

### What to Include

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof of concept
- The affected version(s)
- Any suggested fix, if available

### What to Expect

- **Acknowledgment** within 48 hours of your report
- **Status update** within 7 days with an initial assessment
- **Fix timeline** depends on severity:
  - **Critical/High:** Patch release within 7 days
  - **Medium:** Patch in the next scheduled release
  - **Low:** Fix queued for a future release
- You will be credited in the release notes and GitHub Security Advisory (unless you prefer anonymity)
- We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure)

### Scope

The following are in scope:

- Vulnerabilities in sbom-tools source code
- Dependency vulnerabilities that affect sbom-tools users
- Unsafe parsing of untrusted SBOM inputs (e.g., path traversal, resource exhaustion)

The following are out of scope:

- Vulnerabilities in dependencies that do not affect sbom-tools
- Issues that require physical access to a machine running sbom-tools
- Social engineering attacks

## Security Practices

This project follows supply chain security best practices:

- All dependencies are audited with [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) (advisories, licenses, bans, sources)
- GitHub Actions are pinned to full commit SHAs
- [OpenSSF Scorecard](https://scorecard.dev/) runs weekly to monitor security posture
- Releases are published to crates.io via [Trusted Publishing](https://blog.rust-lang.org/2023/11/09/crates-io-trusted-publishing.html) (OIDC, no long-lived tokens)
- Dependabot monitors for dependency and GitHub Actions updates

# Governance

## Project Model

sbom-tools follows a Benevolent Dictator For Life (BDFL) governance model, common for single-maintainer open source projects at this stage.

## Roles

### Maintainer (BDFL)

- **Alex Matrosov** ([@matrosov](https://github.com/matrosov))
- Final authority on project direction, releases, and code review
- Responsible for security response (see [SECURITY.md](SECURITY.md))

### Contributors

Anyone who submits a pull request, opens an issue, or participates in discussions. All contributions are welcome and reviewed by the maintainer.

### Code Owners

The `CODEOWNERS` file defines review assignment. All changes require maintainer approval.

## Decision Making

- **Day-to-day decisions** (bug fixes, minor features): Maintainer discretion
- **Significant changes** (new commands, architecture, breaking changes): Discussed in a GitHub Issue or PR before implementation
- **Standards and compliance** (new compliance profiles, scoring changes): Documented in the PR with rationale

## Releases

- Versioned with [Semantic Versioning](https://semver.org/)
- Published to [crates.io](https://crates.io/crates/sbom-tools) via automated CI
- Release notes follow the [template](https://github.com/sbom-tool/sbom-tools/releases)

## Access Continuity

- Repository is owned by the `sbom-tool` GitHub organization
- Organization admin access is separate from personal accounts
- If the maintainer becomes unavailable, organization admins can grant access to new maintainers
- All CI/CD uses OIDC tokens (no long-lived secrets that would expire)

## Evolving Governance

As the project grows, this governance model will evolve. Potential future steps:

- Add co-maintainers with commit access
- Establish a core team for shared decision making
- Adopt a consensus-based model if multiple active maintainers emerge

## Contact

- GitHub Issues for public discussion
- Security reports via [SECURITY.md](SECURITY.md)

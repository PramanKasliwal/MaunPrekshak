# Security Policy

## Supported Versions

We actively release security patches, dependency fixes, and vulnerability updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.9.x   | :white_check_mark: |
| 0.8.x   | :white_check_mark: |
| < 0.8.0 | :x:                |

---

## Reporting a Vulnerability

The **MaunPrekshak** project takes the security of our scanner engine, dependencies, and users seriously.

If you discover a security vulnerability in MaunPrekshak:

1. **Do NOT open a public GitHub issue.** Public disclosure puts users at risk before an official patch can be developed and released.
2. Report the vulnerability privately through either:
   - **GitHub Security Advisories**: Navigate to the repository's **[Security tab](https://github.com/PramanKasliwal/maunprekshak/security)** → **Advisories** → **"Report a vulnerability"**
   - **Direct Security Email**: Send details directly to **[me](mailto:kasliwal.praman008@gmail.com)** with the subject line `[SECURITY] MaunPrekshak Vulnerability Report`

---

### What to Include in Your Report

To help us triage and resolve the issue quickly, please provide:

- **Type of Issue**: (e.g., Code Injection, Path Traversal, Credential Leak, Insecure Deserialization, Dependency CVE)
- **Affected Component**: Specific module, function, or CLI flag (e.g., `maunprekshak.scanner.sast`, `mp scan`)
- **Step-by-step Reproduction**: Clear steps, sample input files, or a minimal Proof of Concept (PoC)
- **Potential Impact**: How an attacker could exploit this vulnerability
- **Suggested Fix**: (Optional) Any code recommendations or patches

---

### Response Timeline & SLA

- **Initial Acknowledgement**: Within **48 hours**
- **Vulnerability Triage & Assessment**: Within **5 business days**
- **Status Updates**: Weekly until the fix is released
- **Coordinated Disclosure**: A public security advisory (CVE if applicable) and patched release will be published simultaneously on GitHub and PyPI

---

### Security Hall of Fame

We believe in crediting security researchers who help protect the community through responsible, ethical disclosure. Valid security reports will be acknowledged in:
- Release release notes (`CHANGELOG.md` / GitHub Releases)
- The project documentation security credits

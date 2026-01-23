# Security Policy

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of `http-cli` seriously. If you discover a security vulnerability, please follow these steps:

### 1. **DO NOT** Report Security Vulnerabilities Publicly

Please do not open public GitHub issues for security vulnerabilities, as this could put users at risk.

### 2. Report Privately

**Preferred Method:** Use GitHub's Security Advisory feature:
- Navigate to the [Security tab](https://github.com/cyrenus-sec/http-cli/security/advisories/new)
- Click "Report a vulnerability"
- Provide detailed information about the vulnerability

**Alternative Method:** Email us directly at:
- **Email:** security@cyrenus.com *(or your designated security contact)*
- **Subject:** `[SECURITY] http-cli vulnerability report`

### 3. Include the Following Information

To help us triage and respond quickly, please include:

- **Vulnerability Type** (e.g., injection, authentication bypass, information disclosure)
- **Affected Component** (e.g., scanner module, RBAC checker, compliance reporter)
- **Affected Versions** (which versions are vulnerable)
- **Impact Assessment** (what an attacker could achieve)
- **Proof of Concept** (steps to reproduce, code snippets, or screenshots)
- **Suggested Fix** (if you have one)
- **Your Contact Information** (for follow-up questions)

### 4. Response Timeline

- **Acknowledgment:** Within **48 hours** of report submission
- **Initial Assessment:** Within **5 business days**
- **Patch Development:** Varies by severity, typically **7-30 days**
- **Public Disclosure:** After patch is released and users have time to update

## Security Update Process

1. **Validation:** We verify and reproduce the reported vulnerability
2. **Patch Development:** We develop and test a fix
3. **Advisory Creation:** We create a security advisory (CVE if applicable)
4. **Release:** We publish a patched version
5. **Notification:** We notify users via GitHub releases and security advisories
6. **Public Disclosure:** We coordinate disclosure with the reporter

## Vulnerability Disclosure Policy

We follow **Coordinated Disclosure**:

- We request a **90-day embargo** before public disclosure
- We will credit security researchers in the advisory (unless you prefer anonymity)
- We encourage responsible disclosure and will not pursue legal action against good-faith researchers

## Security Best Practices for Users

When using `http-cli` for security testing:

1. **Always obtain explicit permission** before scanning any systems you don't own
2. **Use `-audit-log`** to maintain accountability records
3. **Enable `-redact`** when sharing scan outputs to avoid leaking sensitive data
4. **Keep the tool updated** to the latest version
5. **Review compliance reports** and remediate findings promptly
6. **Never scan production systems** without proper authorization and change control

## Security Features

This tool includes several security features:

- **Audit Logging:** Cryptographically signed logs (`-audit-log`)
- **Data Redaction:** Automatic masking of secrets (`-redact`)
- **Compliance Mapping:** Maps findings to PCI DSS, HIPAA, GDPR
- **Zero-Trust Validation:** Checks for modern security architecture
- **Sensitive Data Detection:** Identifies leaked credentials, PII, and PHI

## Hall of Fame

We appreciate security researchers who help improve `http-cli`:

<!-- Security researchers who have responsibly disclosed vulnerabilities will be listed here -->

*No security vulnerabilities have been reported yet.*

---

**Last Updated:** 2026-01-23  
**Contact:** m.elqrwash AT gmail 

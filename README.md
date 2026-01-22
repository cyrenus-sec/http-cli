# HTTP-CLI & Security Scanner - Enterprise Edition

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Enterprise Security Features](#enterprise-security-features)
    - [Compliance Reporting](#compliance-reporting)
    - [RBAC & Privilege Escalation](#rbac--privilege-escalation)
    - [Zero-Trust Architecture](#zero-trust-architecture)
    - [Data Governance](#data-governance)
5. [HTTP Request Features](#http-request-features)
6. [Security Scanning](#security-scanning)
7. [Command Reference](#command-reference)
8. [Best Practices](#best-practices)

---

## Introduction

`http-cli` is a comprehensive HTTP client and security vulnerability scanner written in Go. It combines the utility of tools like Postman/cURL with enterprise-grade security testing capabilities, including compliance mapping, role-based access control (RBAC) testing, and Zero-Trust architecture validation.

---

## Installation

### Prerequisites
- Go 1.18 or higher

### Steps

1. **Build the tool:**
   ```bash
   go mod tidy
   go build -o httpcli main.go
   ```

2. **Run:**
   ```bash
   ./httpcli -url "https://api.example.com"
   ```

---

## Basic Usage

### Simple Request
```bash
# GET Request
./httpcli -url "https://api.example.com/users"

# POST with JSON
./httpcli -X POST -url "https://api.example.com/users" \
  -H "Content-Type:application/json" \
  -d '{"name":"John", "role":"admin"}'
```

---

## Enterprise Security Features

### Compliance Reporting
Automatically map security findings to major compliance standards.

**Supported Standards:**
- **PCI DSS**: Payment Card Industry Data Security Standard
- **HIPAA**: Health Insurance Portability and Accountability Act
- **GDPR**: General Data Protection Regulation

**Usage:**
```bash
# Generate a report checking against PCI DSS and GDPR
./httpcli -url "https://api.example.com" -scan -compliance pci,gdpr

# Output JSON report for integration
./httpcli -url "https://api.example.com" -scan -compliance pci -report-format json
```

### RBAC & Privilege Escalation
Automated testing for Broken Access Control. Verify if lower-privileged roles can access high-privilege endpoints.

1. **Create a `roles.json` configuration:**
   ```json
   {
       "roles": [
           {
               "name": "guest",
               "headers": { "Authorization": "Bearer guest-token" }
           },
           {
               "name": "user",
               "headers": { "Authorization": "Bearer user-token" }
           }
       ]
   }
   ```

2. **Run the Scan:**
   ```bash
   # Test if 'guest' or 'user' can access the admin panel
   ./httpcli -url "https://api.example.com/admin/settings" -scan -rbac-config roles.json
   ```

### Zero-Trust Architecture
Validate that your application adheres to Zero-Trust principles: "Never Trust, Always Verify".

**Checks Performed:**
- **Strict Transport Enforcement**: Verifies HSTS with `includeSubDomains`.
- **Modern Encryption**: Enforces TLS 1.2+ (Flags plaintext or weak ciphers).
- **Ubiquitous Authentication**: Flags any endpoint that is publicly accessible (status 200 without auth headers).

**Usage:**
```bash
./httpcli -url "https://api.example.com/resource" -scan -check-architecture zero-trust
```

### Data Governance
Ensure security testing itself is secure and auditable.

- **Audit Logging**: Generates a cryptographically signed log of all actions (`audit.log`).
- **Redaction**: Automatically masks secrets (API Keys, Tokens) in console output.

**Usage:**
```bash
# Run with audit logging and output redaction enabled
./httpcli -url "https://api.example.com" -scan -audit-log -redact
```

---

## HTTP Request Features

Supports all standard HTTP capabilities:
- **Methods**: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS.
- **Headers**: Custom key-value pairs (`-H "Key:Val"`).
- **Body**: Raw string (`-d`) or file-based (`-data-file`).
- **Files**: Multipart upload support (`-f "file=@/path/to.pdf"`).

---

## Security Scanning

The tool includes 15+ built-in vulnerability scanners:
- SQL Injection (`sql`)
- XSS (`xss`)
- Path Traversal (`path`)
- SSRF (`ssrf`)
- XML External Entity (`xxe`)
- Command Injection (`cmd`)
- IDOR (`idor`)
- And more...

**Run a full scan:**
```bash
./httpcli -url "https://target.com" -scan
```

---

## Command Reference

| Flag | Description |
|------|-------------|
| `-url` | Target URL (Required) |
| `-scan` | Enable security scanning mode |
| `-compliance` | Comma-separated standards (pci, hipaa, gdpr) |
| `-rbac-config` | Path to RBAC JSON config file |
| `-check-architecture` | Architecture mode (e.g., `zero-trust`) |
| `-audit-log` | Enable signed audit logging |
| `-redact` | Mask sensitive data in output |
| `-report-format` | Report output format (text, json) |
| `-X` | HTTP Method (default GET) |
| `-H` | Headers (Key:Value,Key:Value) |
| `-d` | Request body data |
| `-f` | Multipart file uploads |

---

## Best Practices

1. **Zero-Trust**: Always run with `-check-architecture zero-trust` when auditing internal services to ensure no implicit trust exists.
2. **Compliance**: Use `-compliance` flags during CI/CD pipelines to catch violations early.
3. **Audit**: Enable `-audit-log` when performing penetration tests for client accountability.
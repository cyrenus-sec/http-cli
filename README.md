# HTTP Client & Security Scanner - Complete Documentation

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [HTTP Request Features](#http-request-features)
5. [Security Scanning](#security-scanning)
6. [Command Reference](#command-reference)
7. [Examples](#examples)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)

---

## Introduction

This tool is a comprehensive HTTP client and security vulnerability scanner written in Go. It serves as a Postman alternative with built-in security testing capabilities.

### Features
- ✅ All HTTP methods (GET, POST, PUT, DELETE, PATCH, etc.)
- ✅ Custom headers and authentication
- ✅ Multiple body formats (JSON, form-data, raw text)
- ✅ File uploads (single and multiple)
- ✅ Response saving to files
- ✅ Verbose output mode
- ✅ Security vulnerability scanning (15+ test types)
- ✅ Pretty-printed JSON responses
- ✅ Configurable timeouts

---

## Installation

### Prerequisites
- Go 1.16 or higher

### Steps


1. **Build the tool:**
   ```bash
   go build -o httpcli main.go
   ```

2. **Make it executable (Linux/Mac):**
   ```bash
   chmod +x httpcli
   ```

3. **Optional - Add to PATH:**
   ```bash
   # Linux/Mac
   sudo mv httpcli /usr/local/bin/

   # Windows - add the directory to your PATH environment variable
   ```

---

## Basic Usage

### Simple GET Request
```bash
httpcli -url "https://api.example.com/users"
```

### Simple POST Request
```bash
httpcli -X POST -url "https://api.example.com/users" -d '{"name":"John"}'
```

---

## HTTP Request Features

### 1. HTTP Methods

Use the `-X` flag to specify the HTTP method:

```bash
# GET (default)
httpcli -url "https://api.example.com/users"

# POST
httpcli -X POST -url "https://api.example.com/users"

# PUT
httpcli -X PUT -url "https://api.example.com/users/1"

# DELETE
httpcli -X DELETE -url "https://api.example.com/users/1"

# PATCH
httpcli -X PATCH -url "https://api.example.com/users/1"

# HEAD
httpcli -X HEAD -url "https://api.example.com/users"

# OPTIONS
httpcli -X OPTIONS -url "https://api.example.com/users"
```

### 2. Headers

Add custom headers using the `-H` flag:

```bash
# Single header
httpcli -url "https://api.example.com/users" -H "Content-Type:application/json"

# Multiple headers (comma-separated)
httpcli -url "https://api.example.com/users" \
  -H "Content-Type:application/json,Authorization:Bearer YOUR_TOKEN,Accept:application/json"
```

**Common header examples:**
```bash
# JSON content type
-H "Content-Type:application/json"

# Bearer token authentication
-H "Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Basic authentication (alternative)
-H "Authorization:Basic dXNlcjpwYXNzd29yZA=="

# API key
-H "X-API-Key:your-api-key-here"

# User agent
-H "User-Agent:MyApp/1.0"

# Accept header
-H "Accept:application/json"
```

### 3. Request Body

#### Raw Body Data
```bash
# JSON body
httpcli -X POST -url "https://api.example.com/users" \
  -H "Content-Type:application/json" \
  -d '{"name":"John Doe","email":"john@example.com","age":30}'

# Plain text
httpcli -X POST -url "https://api.example.com/text" \
  -d "This is plain text data"

# XML body
httpcli -X POST -url "https://api.example.com/xml" \
  -H "Content-Type:application/xml" \
  -d '<?xml version="1.0"?><user><name>John</name></user>'
```

#### Body from File
```bash
# Read request body from a file
httpcli -X POST -url "https://api.example.com/users" \
  -H "Content-Type:application/json" \
  -data-file payload.json
```

### 4. Form Data

Send form-urlencoded or multipart form data:

```bash
# Simple form data
httpcli -X POST -url "https://api.example.com/form" \
  -F "username=john,password=secret123,remember=true"

# Form data with multiple values
httpcli -X POST -url "https://api.example.com/register" \
  -F "name=John Doe,email=john@example.com,age=30,country=USA"
```

### 5. File Uploads

#### Single File Upload
```bash
httpcli -X POST -url "https://api.example.com/upload" \
  -f "file=@/path/to/document.pdf"
```

#### Multiple File Uploads
```bash
httpcli -X POST -url "https://api.example.com/upload" \
  -f "photo=@/home/user/image.jpg,document=@/home/user/report.pdf"
```

#### File Upload with Form Data
```bash
httpcli -X POST -url "https://api.example.com/submit" \
  -F "title=My Report,description=Annual Report 2024" \
  -f "file=@/path/to/report.pdf,thumbnail=@/path/to/thumb.jpg"
```

**Supported file types:** All file types are supported (PDF, images, documents, videos, etc.)

### 6. Timeout Configuration

Set request timeout in seconds:

```bash
# 10 second timeout
httpcli -url "https://slow-api.example.com" -timeout 10

# 60 second timeout for large uploads
httpcli -X POST -url "https://api.example.com/upload" \
  -f "video=@/path/to/large-video.mp4" \
  -timeout 60
```

### 7. Verbose Output

Enable detailed request/response information:

```bash
httpcli -url "https://api.example.com/users" -v
```

**Verbose output includes:**
- Request method and URL
- All request headers
- All response headers
- Response time
- Response body

### 8. Save Response to File

Save the response body to a file:

```bash
# Save JSON response
httpcli -url "https://api.example.com/data" -o response.json

# Save image
httpcli -url "https://example.com/image.jpg" -o image.jpg

# Save with verbose output
httpcli -url "https://api.example.com/report" -o report.pdf -v
```

---

## Security Scanning

### Overview

The security scanner tests for 15+ vulnerability types across your web applications and APIs.

### Basic Security Scan

```bash
# Full scan (all vulnerability types)
httpcli -url "https://target-site.com/api" -scan

# Scan with authentication
httpcli -url "https://api.example.com/endpoint" \
  -H "Authorization:Bearer TOKEN" \
  -scan
```

### Scan Specific Vulnerabilities

Use the `-scan-type` flag to test specific vulnerability categories:

```bash
# SQL Injection only
httpcli -url "https://api.example.com/search" -scan -scan-type sql

# XSS only
httpcli -url "https://api.example.com/comment" -scan -scan-type xss

# Multiple specific tests
httpcli -url "https://api.example.com" -scan -scan-type sql
httpcli -url "https://api.example.com" -scan -scan-type xss
```

### Available Scan Types

| Scan Type | Description | Severity |
|-----------|-------------|----------|
| `sql` | SQL Injection | Critical |
| `nosql` | NoSQL Injection | Critical |
| `xss` | Cross-Site Scripting | High |
| `xxe` | XML External Entity | Critical |
| `ssrf` | Server-Side Request Forgery | Critical |
| `cmd` | Command Injection | Critical |
| `ldap` | LDAP Injection | High |
| `path` | Path Traversal | Critical |
| `idor` | Insecure Direct Object Reference | High |
| `header` | Header Injection | Medium |
| `cors` | CORS Misconfiguration | Medium/High |
| `clickjack` | Clickjacking | Medium |
| `ssl` | SSL/TLS Configuration | Medium/High |
| `info` | Information Disclosure | Low |
| `auth` | Authentication Weakness | Critical/High |
| `all` | All of the above | - |

---

## Command Reference

### All Available Flags

```
-url string
    Request URL (required for all operations)

-X string
    HTTP method (default "GET")
    Options: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS

-H string
    Headers in format 'Key1:Value1,Key2:Value2'

-d string
    Request body data

-data-file string
    File containing request body

-F string
    Form data in format 'key1=value1,key2=value2'

-f string
    Files to upload in format 'field1=@/path/file1,field2=@/path/file2'

-timeout int
    Request timeout in seconds (default 30)

-v
    Verbose output (shows full request/response details)

-o string
    Save response to file

-scan
    Run security vulnerability scan

-scan-type string
    Specific scan type (default "all")
    Options: sql, xss, path, header, cmd, xxe, ssrf, idor, 
             nosql, ldap, cors, clickjack, ssl, info, auth, all
```

---

## Examples

### Example 1: REST API Testing

```bash
# GET all users
httpcli -url "https://api.example.com/users"

# GET specific user
httpcli -url "https://api.example.com/users/123"

# CREATE new user
httpcli -X POST -url "https://api.example.com/users" \
  -H "Content-Type:application/json,Authorization:Bearer TOKEN" \
  -d '{"name":"Jane Doe","email":"jane@example.com"}'

# UPDATE user
httpcli -X PUT -url "https://api.example.com/users/123" \
  -H "Content-Type:application/json,Authorization:Bearer TOKEN" \
  -d '{"name":"Jane Smith"}'

# DELETE user
httpcli -X DELETE -url "https://api.example.com/users/123" \
  -H "Authorization:Bearer TOKEN"
```

### Example 2: Authentication

```bash
# Login request
httpcli -X POST -url "https://api.example.com/auth/login" \
  -H "Content-Type:application/json" \
  -d '{"username":"user@example.com","password":"secret123"}'

# Use token from login response
httpcli -url "https://api.example.com/profile" \
  -H "Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Basic Authentication
httpcli -url "https://api.example.com/protected" \
  -H "Authorization:Basic dXNlcjpwYXNzd29yZA=="
```

### Example 3: File Operations

```bash
# Upload profile picture
httpcli -X POST -url "https://api.example.com/users/123/avatar" \
  -H "Authorization:Bearer TOKEN" \
  -f "avatar=@/home/user/photo.jpg"

# Upload document with metadata
httpcli -X POST -url "https://api.example.com/documents" \
  -H "Authorization:Bearer TOKEN" \
  -F "title=Report 2024,category=financial,public=false" \
  -f "file=@/home/user/report.pdf"

# Download file
httpcli -url "https://api.example.com/files/report.pdf" \
  -H "Authorization:Bearer TOKEN" \
  -o downloaded_report.pdf
```

### Example 4: GraphQL

```bash
# GraphQL query
httpcli -X POST -url "https://api.example.com/graphql" \
  -H "Content-Type:application/json" \
  -d '{"query":"{ users { id name email } }"}'

# GraphQL mutation
httpcli -X POST -url "https://api.example.com/graphql" \
  -H "Content-Type:application/json" \
  -d '{"query":"mutation { createUser(name: \"John\", email: \"john@example.com\") { id } }"}'
```

### Example 5: Webhooks Testing

```bash
# Test webhook payload
httpcli -X POST -url "https://your-app.com/webhook" \
  -H "Content-Type:application/json,X-Webhook-Signature:sha256=abc123" \
  -d '{"event":"payment.success","data":{"amount":100,"currency":"USD"}}'
```

### Example 6: Security Testing

```bash
# Full security audit
httpcli -url "https://target-app.com/api/users" -scan -v

# Test authentication endpoint for SQL injection
httpcli -url "https://target-app.com/login" -scan -scan-type sql

# Test file upload for path traversal
httpcli -url "https://target-app.com/upload" -scan -scan-type path

# Test API for SSRF vulnerabilities
httpcli -url "https://target-app.com/api/fetch" -scan -scan-type ssrf

# Comprehensive scan with results saved
httpcli -url "https://target-app.com" -scan -v > security_report.txt
```

### Example 7: API Development Workflow

```bash
# Test during development (verbose mode)
httpcli -X POST -url "http://localhost:3000/api/users" \
  -H "Content-Type:application/json" \
  -d '{"name":"Test User"}' \
  -v

# Test with different environments
httpcli -url "http://localhost:3000/health" # Development
httpcli -url "https://staging-api.example.com/health" # Staging
httpcli -url "https://api.example.com/health" # Production

# Performance testing (check response times)
httpcli -url "https://api.example.com/heavy-endpoint" -v -timeout 5
```

---

## Best Practices

### 1. Security Scanning Best Practices

**DO:**
- ✅ Only scan systems you own or have written permission to test
- ✅ Run scans during off-peak hours to minimize impact
- ✅ Save scan results for documentation: `httpcli -url "..." -scan > report.txt`
- ✅ Verify findings manually before reporting
- ✅ Use `-v` flag for detailed analysis
- ✅ Test in staging environments first

**DON'T:**
- ❌ Scan production systems without approval
- ❌ Run aggressive scans during business hours
- ❌ Test third-party systems without authorization
- ❌ Ignore rate limiting or WAF responses
- ❌ Assume all findings are true positives

### 2. API Testing Best Practices

```bash
# Use environment variables for sensitive data
export API_TOKEN="your-token-here"
httpcli -url "https://api.example.com/users" -H "Authorization:Bearer $API_TOKEN"

# Save request templates
echo '{"name":"","email":""}' > user_template.json
httpcli -X POST -url "https://api.example.com/users" -data-file user_template.json

# Test error handling
httpcli -X POST -url "https://api.example.com/users" -d '{"invalid":"data"}'
httpcli -X GET -url "https://api.example.com/users/999999"
```

### 3. Debugging Tips

```bash
# Use verbose mode to see full request/response
httpcli -url "https://api.example.com/endpoint" -v

# Increase timeout for slow endpoints
httpcli -url "https://slow-api.example.com" -timeout 60 -v

# Save responses for analysis
httpcli -url "https://api.example.com/data" -o response.json -v

# Test with different HTTP methods
for method in GET POST PUT DELETE; do
  echo "Testing $method"
  httpcli -X $method -url "https://api.example.com/test"
done
```

### 4. Automation Scripts

```bash
#!/bin/bash
# Automated API health check

ENDPOINTS=(
  "https://api.example.com/health"
  "https://api.example.com/users"
  "https://api.example.com/products"
)

for endpoint in "${ENDPOINTS[@]}"; do
  echo "Checking $endpoint"
  httpcli -url "$endpoint" -H "Authorization:Bearer $TOKEN" -timeout 5
done
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Connection Timeout
```
Error: error executing request: context deadline exceeded
```

**Solutions:**
- Increase timeout: `-timeout 60`
- Check network connectivity
- Verify URL is correct and accessible

#### 2. SSL/TLS Errors
```
Error: x509: certificate signed by unknown authority
```

**Solutions:**
- Verify the server's SSL certificate is valid
- Check system time/date is correct
- Update system certificates

#### 3. Authentication Failures
```
Status: 401 Unauthorized
```

**Solutions:**
- Verify token/credentials are correct
- Check header format: `Authorization:Bearer TOKEN` (no spaces after colon)
- Ensure token hasn't expired

#### 4. File Upload Issues
```
Error: error opening file
```

**Solutions:**
- Verify file path is correct
- Use absolute paths: `/home/user/file.pdf`
- Check file permissions
- Ensure `@` prefix: `-f "file=@/path/to/file"`

#### 5. Scan Not Finding Vulnerabilities
```
Total Tests: 50
Vulnerabilities Found: 0
```

**Possible Reasons:**
- Application is actually secure (good!)
- WAF/security controls are blocking test payloads
- Endpoint requires different attack vectors
- False negatives (manual testing recommended)

#### 6. Rate Limiting
```
Status: 429 Too Many Requests
```

**Solutions:**
- Scan has built-in 100ms delay between requests
- Increase delay in code if needed
- Use `-timeout` to handle slow responses
- Scan fewer endpoints at once

#### 7. Large Response Handling
```
Response too large
```

**Solutions:**
- Save to file: `-o output.json`
- Increase timeout for large responses
- Use pagination if API supports it

### Debug Mode

For maximum debugging information:
```bash
httpcli -url "https://api.example.com" -v -timeout 30 > debug.log 2>&1
```

---

## Advanced Usage

### 1. Scripting with httpcli

```bash
#!/bin/bash
# Test suite for API

BASE_URL="https://api.example.com"
TOKEN="your-token"

# Test 1: Health check
echo "=== Health Check ==="
httpcli -url "$BASE_URL/health"

# Test 2: Authentication
echo "=== Testing Authentication ==="
RESPONSE=$(httpcli -X POST -url "$BASE_URL/auth/login" \
  -H "Content-Type:application/json" \
  -d '{"username":"test","password":"test123"}')
echo "$RESPONSE"

# Test 3: CRUD operations
echo "=== Testing CRUD ==="
httpcli -X POST -url "$BASE_URL/users" \
  -H "Content-Type:application/json,Authorization:Bearer $TOKEN" \
  -d '{"name":"Test User"}'

# Test 4: Security scan
echo "=== Security Scan ==="
httpcli -url "$BASE_URL/api" -scan -scan-type sql
```

### 2. CI/CD Integration

```yaml
# .github/workflows/api-test.yml
name: API Security Test

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2
      
      - name: Setup Go
        uses: actions/setup-go@v2
        with:
          go-version: 1.19
      
      - name: Build Tool
        run: go build -o httpcli main.go
      
      - name: Run Security Scan
        run: |
          ./httpcli -url "https://staging-api.example.com" -scan > scan_results.txt
          cat scan_results.txt
      
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-scan-results
          path: scan_results.txt
```

### 3. Response Parsing

```bash
# Using jq to parse JSON responses
httpcli -url "https://api.example.com/users" | jq '.data[] | {id, name}'

# Extract specific field
USER_ID=$(httpcli -X POST -url "https://api.example.com/users" \
  -H "Content-Type:application/json" \
  -d '{"name":"John"}' | jq -r '.id')

echo "Created user with ID: $USER_ID"
```

---

## Security Scan Report Interpretation

### Understanding Scan Results

#### Severity Levels

- 🔴 **Critical**: Requires immediate attention. Exploitable vulnerabilities that can lead to system compromise.
- 🟠 **High**: Serious security issues that should be addressed quickly.
- ⚠️ **Medium**: Security weaknesses that should be reviewed and fixed.
- 🟢 **Low**: Minor issues or information disclosure that should be addressed over time.

#### Example Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 SECURITY VULNERABILITY SCAN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target: https://example.com/api
Scan Type: all

→ Testing SQL Injection vulnerabilities...
→ Testing XSS vulnerabilities...
...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 SCAN RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 [Critical] SQL Injection
   Payload: ' OR '1'='1
   Status: 200
   Evidence: SQL error detected: mysql

🟠 [High] XSS
   Payload: <script>alert('XSS')</script>
   Status: 200
   Evidence: Payload reflected in response

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📈 SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Tests: 100
Vulnerabilities Found: 2
  Critical: 1
  High: 1
  Medium: 0
```

---

## Legal and Ethical Considerations

### ⚠️ IMPORTANT WARNING

**Only use this tool on systems you own or have explicit written permission to test.**

Unauthorized security testing is illegal in most jurisdictions and may result in:
- Criminal prosecution
- Civil lawsuits
- Network bans
- Legal liability

### Responsible Disclosure

If you find vulnerabilities:
1. Document the findings carefully
2. Contact the system owner privately
3. Allow reasonable time for fixes (typically 90 days)
4. Do not publicly disclose details until patched

### Bug Bounty Programs

Many companies have bug bounty programs that legally authorize security testing. Check:
- HackerOne
- Bugcrowd
- Company security pages

---

## Support and Contributing

### Getting Help

If you encounter issues:
1. Check this documentation
2. Review the troubleshooting section
3. Verify your command syntax
4. Test with verbose mode (`-v`)

### Feature Requests

This tool can be extended with:
- Additional vulnerability tests
- Custom payload files
- Report generation (HTML/PDF)
- Proxy support
- Cookie management
- Session handling

---

## Version History

**v1.0.0** - Initial release
- HTTP client functionality
- 15+ vulnerability tests
- File upload support
- Verbose output mode

---

## License and Disclaimer

This tool is provided for educational and authorized testing purposes only. The authors assume no liability for misuse or damage caused by this tool. Always obtain proper authorization before testing any system you do not own.

---

**Happy (Ethical) Testing! 🔒**
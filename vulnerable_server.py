#!/usr/bin/env python3
"""
Comprehensive Vulnerable Test Server for http-cli Security Scanner
Provides endpoints to test all vulnerability types and compliance checks
"""

import http.server
import socketserver
import urllib.parse
import json
import base64
from datetime import datetime

class VulnerableHandler(http.server.SimpleHTTPRequestHandler):
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass
    
    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        # SQL Injection via POST body
        if path == "/api/login":
            try:
                data = json.loads(post_data)
                username = data.get('username', '')
                
                if "'" in username or "OR" in username.upper():
                    response = {"error": "SQL syntax error near '" + username + "'"}
                else:
                    response = {"status": "Invalid credentials"}
                    
                self.send_json_response(response, 200)
            except:
                self.send_json_response({"error": "Invalid JSON"}, 400)
            return
        
        # XXE Endpoint
        if path == "/api/xml":
            if "<!ENTITY" in post_data or "<!DOCTYPE" in post_data:
                response = {
                    "result": "root:x:0:0:root:/root:/bin/bash",  # Simulated file read
                    "warning": "XXE detected"
                }
            else:
                response = {"result": "XML processed"}
            self.send_json_response(response, 200)
            return
        
        # NoSQL Injection
        if path == "/api/users":
            if "$ne" in post_data or "$gt" in post_data:
                response = {
                    "users": [
                        {"username": "admin", "email": "admin@example.com"},
                        {"username": "user1", "email": "user1@example.com"}
                    ],
                    "note": "NoSQL injection bypassed authentication"
                }
            else:
                response = {"users": []}
            self.send_json_response(response, 200)
            return
        
        # Default POST response
        self.send_json_response({"message": "POST received"}, 200)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # ============ SQL INJECTION TESTS ============
        if path == "/api/user":
            user_id = params.get('id', [''])[0]
            if "'" in user_id or "OR" in user_id.upper() or "--" in user_id:
                response = {
                    "error": "SQL syntax error near '" + user_id + "'",
                    "query": f"SELECT * FROM users WHERE id = '{user_id}'"
                }
            else:
                response = {"id": user_id, "name": "John Doe"}
            self.send_json_response(response, 200)
            return

        # ============ XSS TESTS ============
        if path == "/api/search":
            query = params.get('q', [''])[0]
            # Vulnerable: reflects user input without sanitization
            response = {
                "query": query,
                "results": f"<div>You searched for: {query}</div>"
            }
            self.send_json_response(response, 200)
            return

        # ============ PATH TRAVERSAL TEST ============
        if path == "/api/file":
            filename = params.get('file', [''])[0]
            if "../" in filename or "..\\" in filename:
                response = {
                    "content": "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin",
                    "warning": "Path traversal detected"
                }
            else:
                response = {"content": "Normal file content"}
            self.send_json_response(response, 200)
            return

        # ============ COMMAND INJECTION TEST ============
        if path == "/api/ping":
            host = params.get('host', ['localhost'])[0]
            if ";" in host or "|" in host or "`" in host or "$(" in host:
                response = {
                    "output": "uid=0(root) gid=0(root) groups=0(root)\ntotal 48K",
                    "warning": "Command injection detected"
                }
            else:
                response = {"output": f"PING {host}: 64 bytes from {host}: icmp_seq=1 ttl=64 time=0.123 ms"}
            self.send_json_response(response, 200)
            return

        # ============ SSRF TEST ============
        if path == "/api/fetch":
            url = params.get('url', [''])[0]
            if "localhost" in url or "127.0.0.1" in url or "169.254.169.254" in url:
                response = {
                    "data": "ami-id: ami-12345\ninstance-id: i-1234567890abcdef0",
                    "warning": "SSRF to internal service detected"
                }
            else:
                response = {"data": "External content"}
            self.send_json_response(response, 200)
            return

        # ============ IDOR TEST ============
        if path == "/api/profile":
            user_id = params.get('id', ['1'])[0]
            # Different responses for different IDs (IDOR vulnerability)
            response = {
                "id": user_id,
                "email": f"user{user_id}@example.com",
                "ssn": f"123-45-{user_id.zfill(4)}",
                "warning": "IDOR: Can access other users' data"
            }
            self.send_json_response(response, 200)
            return

        # ============ LDAP INJECTION TEST ============
        if path == "/api/ldap":
            username = params.get('username', [''])[0]
            if "*" in username or ")(uid" in username or ")(|" in username:
                response = {
                    "users": [
                        {"dn": "cn=admin,dc=example,dc=com"},
                        {"dn": "cn=user1,dc=example,dc=com"},
                        {"dn": "cn=user2,dc=example,dc=com"}
                    ],
                    "warning": "LDAP injection detected"
                }
            else:
                response = {"users": []}
            self.send_json_response(response, 200)
            return

        # ============ CORS MISCONFIGURATION TEST ============
        if path == "/api/cors":
            origin = self.headers.get('Origin', '')
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            # Vulnerable: Reflects any origin
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            response = {"data": "sensitive information", "session": "abc123"}
            self.wfile.write(json.dumps(response).encode())
            return

        # ============ CLICKJACKING TEST (Missing headers) ============
        if path == "/api/transfer":
            # Intentionally missing X-Frame-Options
            response = {"status": "Transfer initiated", "amount": 1000}
            self.send_json_response(response, 200)
            return

        # ============ SSL/TLS TEST (HTTP instead of HTTPS) ============
        if path == "/api/secure":
            response = {
                "warning": "This is served over HTTP, not HTTPS",
                "data": "Sensitive information"
            }
            self.send_json_response(response, 200)
            return

        # ============ INFORMATION DISCLOSURE TEST ============
        if path == "/api/debug":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Server", "Apache/2.4.29 (Ubuntu)")
            self.send_header("X-Powered-By", "PHP/7.2.19")
            self.send_header("X-AspNet-Version", "4.0.30319")
            self.end_headers()
            response = {
                "debug": True,
                "stack_trace": "Error at line 42 in /var/www/app.py",
                "database": "mysql://user:pass@localhost/db"
            }
            self.wfile.write(json.dumps(response).encode())
            return

        # ============ AUTHENTICATION WEAKNESS TEST ============
        if path == "/api/admin":
            auth_header = self.headers.get('Authorization', '')
            
            # Check for weak credentials
            if auth_header:
                try:
                    auth_type, credentials = auth_header.split(' ', 1)
                    if auth_type.lower() == 'basic':
                        decoded = base64.b64decode(credentials).decode('utf-8')
                        username, password = decoded.split(':', 1)
                        
                        # Weak credential check
                        weak_creds = [
                            ('admin', 'admin'),
                            ('admin', 'password'),
                            ('admin', '123456'),
                            ('root', 'root'),
                            ('test', 'test')
                        ]
                        
                        if (username, password) in weak_creds:
                            response = {
                                "status": "authenticated",
                                "role": "admin",
                                "message": "Weak credentials accepted"
                            }
                            self.send_json_response(response, 200)
                            return
                except:
                    pass
            
            # Allow access without authentication (weakness)
            response = {
                "status": "access_granted",
                "message": "No authentication required",
                "admin_panel": True
            }
            self.send_json_response(response, 200)
            return

        # ============ HEADER INJECTION TEST ============
        if path == "/api/redirect":
            url = params.get('url', [''])[0]
            self.send_response(302)
            # Vulnerable to header injection via CRLF
            self.send_header("Location", url)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            return

        # ============ PCI DSS COMPLIANCE TEST ============
        if path == "/pci/payment":
            response = {
                "status": "success",
                "card_number": params.get("card", ["4111111111111111"])[0],
                "cvv": params.get("cvv", ["123"])[0],
                "expiry": "12/26",
                "holder": "John Doe"
            }
            self.send_json_response(response, 200)
            return

        # ============ HIPAA COMPLIANCE TEST ============
        if path == "/hipaa/patient":
            response = {
                "patient_name": "John Doe",
                "medical_record_number": "MRN-88442",
                "diagnosis": "Diabetes Type II",
                "doctor": "Dr. Smith",
                "ssn": "123-45-6789",
                "dob": "1980-01-15"
            }
            self.send_json_response(response, 200)
            return

        # ============ GDPR COMPLIANCE TEST ============
        if path == "/gdpr/user":
            response = {
                "full_name": "Anna Müller",
                "email": "anna@example.com",
                "national_id": "DE123456789",
                "ip_address": self.client_address[0],
                "location": "Berlin, Germany",
                "phone": "+49 30 12345678"
            }
            self.send_json_response(response, 200)
            return

        # ============ RBAC TEST ENDPOINTS ============
        if path == "/rbac/admin":
            # Should require admin role
            auth = self.headers.get('Authorization', '')
            role = self.headers.get('X-Role', '')
            
            if 'admin' in auth.lower() or role.lower() == 'admin':
                response = {"access": "granted", "role": "admin", "data": "sensitive admin data"}
            else:
                response = {"access": "granted", "role": "guest", "warning": "RBAC violation - guest accessed admin endpoint"}
            
            self.send_json_response(response, 200)
            return

        if path == "/rbac/user":
            # Should be accessible to any authenticated user
            response = {"access": "granted", "data": "user data"}
            self.send_json_response(response, 200)
            return

        # ============ ZERO-TRUST TEST (HTTP, no HSTS) ============
        if path == "/zerotrust/api":
            # Intentionally missing HSTS and served over HTTP
            response = {
                "data": "This endpoint violates Zero-Trust principles",
                "warnings": [
                    "No HSTS header",
                    "Served over HTTP",
                    "No authentication required"
                ]
            }
            self.send_json_response(response, 200)
            return

        # ============ DEFAULT / API INFO ============
        if path == "/" or path == "/api":
            response = {
                "message": "Vulnerable Test API for http-cli Scanner",
                "version": "1.0",
                "endpoints": {
                    "sql_injection": "/api/user?id=1",
                    "xss": "/api/search?q=test",
                    "path_traversal": "/api/file?file=test.txt",
                    "command_injection": "/api/ping?host=localhost",
                    "ssrf": "/api/fetch?url=http://example.com",
                    "idor": "/api/profile?id=1",
                    "ldap": "/api/ldap?username=test",
                    "cors": "/api/cors",
                    "clickjacking": "/api/transfer",
                    "info_disclosure": "/api/debug",
                    "auth_weakness": "/api/admin",
                    "header_injection": "/api/redirect?url=http://example.com",
                    "pci_compliance": "/pci/payment",
                    "hipaa_compliance": "/hipaa/patient",
                    "gdpr_compliance": "/gdpr/user",
                    "rbac": "/rbac/admin",
                    "zerotrust": "/zerotrust/api",
                    "post_endpoints": {
                        "login": "POST /api/login",
                        "xxe": "POST /api/xml",
                        "nosql": "POST /api/users"
                    }
                }
            }
            self.send_json_response(response, 200)
            return

        # ============ 404 FOR UNKNOWN PATHS ============
        self.send_json_response({"error": "Not found"}, 404)

    def send_json_response(self, data, status=200):
        """Helper to send JSON responses"""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())


PORT = 8000

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), VulnerableHandler) as httpd:
        print(f"╔══════════════════════════════════════════════════════════╗")
        print(f"║  Vulnerable Test Server for http-cli Security Scanner   ║")
        print(f"╠══════════════════════════════════════════════════════════╣")
        print(f"║  Port: {PORT:<50} ║")
        print(f"║  URL:  http://localhost:{PORT}/                           ║")
        print(f"╠══════════════════════════════════════════════════════════╣")
        print(f"║  Available Test Endpoints:                               ║")
        print(f"║  - SQL Injection, XSS, Path Traversal                    ║")
        print(f"║  - Command Injection, SSRF, IDOR                         ║")
        print(f"║  - LDAP, NoSQL, XXE Injection                            ║")
        print(f"║  - CORS, Clickjacking, SSL/TLS                           ║")
        print(f"║  - Information Disclosure, Auth Weaknesses               ║")
        print(f"║  - PCI, HIPAA, GDPR Compliance Tests                     ║")
        print(f"║  - RBAC, Zero-Trust Tests                                ║")
        print(f"╠══════════════════════════════════════════════════════════╣")
        print(f"║  Visit http://localhost:{PORT}/api for endpoint list        ║")
        print(f"╚══════════════════════════════════════════════════════════╝")
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Server started. Press Ctrl+C to stop.\n")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Server stopped.")

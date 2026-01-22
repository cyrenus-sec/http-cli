import http.server
import socketserver
import urllib.parse
import json

class VulnerableHandler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        # ---------- PCI DSS TEST ----------
        if path == "/pci/payment":
            response = {
                "status": "success",
                "card_number": params.get("card", ["4111111111111111"])[0],
                "cvv": params.get("cvv", ["123"])[0],
                "expiry": "12/26"
            }
            self.wfile.write(json.dumps(response).encode())
            return

        # ---------- HIPAA TEST ----------
        if path == "/hipaa/patient":
            response = {
                "patient_name": "John Doe",
                "medical_record_number": "MRN-88442",
                "diagnosis": "Diabetes Type II",
                "doctor": "Dr. Smith"
            }
            self.wfile.write(json.dumps(response).encode())
            return

        # ---------- GDPR TEST ----------
        if path == "/gdpr/user":
            response = {
                "full_name": "Anna Müller",
                "email": "anna@example.com",
                "national_id": "DE123456789",
                "ip_address": self.client_address[0]
            }
            self.wfile.write(json.dumps(response).encode())
            return

        # ---------- DEFAULT ----------
        self.wfile.write(json.dumps({"message": "Hello insecure world"}).encode())


PORT = 8000

with socketserver.TCPServer(("", PORT), VulnerableHandler) as httpd:
    print(f"Serving vulnerable test API on port {PORT}")
    httpd.serve_forever()

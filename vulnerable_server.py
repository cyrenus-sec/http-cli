
import http.server
import socketserver
import urllib.parse

class VulnerableHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)

        if 'id' in params:
            # Simulate a SQL injection vulnerability
            response = f"User ID: {params['id'][0]}"
            if "'" in params['id'][0]:
                response = "SQL syntax error"
        else:
            response = "Hello, world!"

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(response.encode())

PORT = 8000

with socketserver.TCPServer(("", PORT), VulnerableHandler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()

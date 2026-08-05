#!/usr/bin/env python3
"""
Mock Auth Server for AVATARIKA Game
Mimics the Gamexp authentication endpoints to bypass the launcher requirement.

Endpoints:
- POST /lp/v2/api.php - Authentication API
- GET /health - Health check
- GET /authenticator - Authenticator info
"""

import http.server
import json
import hashlib
import uuid
from datetime import datetime
from urllib.parse import urlparse

AUTH_TOKEN = "mock_auth_token_" + uuid.uuid4().hex[:16]
SESSION_ID = "mock_session_" + uuid.uuid4().hex[:16]
HMAC_KEY = hashlib.sha256(b"mock_hmac_key").hexdigest()

class AuthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {self.client_address[0]} - {format % args}")

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_error_json(self, message, status=400):
        self.send_json({"error": message, "statusCode": status}, status)

    def read_body(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            return json.loads(self.rfile.read(content_length))
        return {}

    def do_POST(self):
        parsed = urlparse(self.path)
        
        if parsed.path == '/lp/v2/api.php':
            self.handle_auth_api()
        else:
            self.send_error_json(f"Unknown endpoint: {parsed.path}", 404)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == '/health':
            self.handle_health()
        elif parsed.path == '/authenticator':
            self.handle_authenticator()
        elif parsed.path == '/api.php':
            self.handle_auth_api()
        else:
            self.send_error_json(f"Unknown endpoint: {parsed.path}", 404)

    def handle_auth_api(self):
        """Handle authentication API requests"""
        print("\n=== AUTH API REQUEST ===")
        body = self.read_body()
        print(f"  Method: {self.command}")
        print(f"  Path: {self.path}")
        print(f"  Body: {json.dumps(body, indent=2)}")

        # Simulate authentication flow
        auth_token = AUTH_TOKEN
        session_id = SESSION_ID
        token_expires = int(datetime.now().timestamp()) + 86400  # 24 hours

        response = {
            "authToken": auth_token,
            "sessionId": session_id,
            "tokenExpiry": token_expires,
            "hmacKey": HMAC_KEY,
            "status": "success",
            "statusCode": 200,
            "timestamp": datetime.now().isoformat(),
            "version": "2.0.0"
        }

        self.send_json(response, 200)
        print(f"  Response: auth_token={auth_token[:20]}..., status=success")

    def handle_health(self):
        """Handle health check requests"""
        print("\n=== HEALTH CHECK ===")
        response = {
            "status": "ok",
            "version": "3.2.4",
            "uptime": "mock",
            "timestamp": datetime.now().isoformat()
        }
        self.send_json(response, 200)
        print(f"  Response: status=ok")

    def handle_authenticator(self):
        """Handle authenticator info requests"""
        print("\n=== AUTHENTICATOR ===")
        response = {
            "authenticator": "mock_auth",
            "version": "1.0.0",
            "status": "active",
            "timestamp": datetime.now().isoformat()
        }
        self.send_json(response, 200)
        print(f"  Response: authenticator=mock_auth")

def main():
    port = 8443
    print(f"Starting mock auth server on http://127.0.0.1:{port}")
    print(f"  Auth API:    POST http://127.0.0.1:{port}/lp/v2/api.php")
    print(f"  Health Check: GET http://127.0.0.1:{port}/health")
    print(f"  Authenticator: GET http://127.0.0.1:{port}/authenticator")
    print()

    server = http.server.HTTPServer(('127.0.0.1', port), AuthHandler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()

if __name__ == '__main__':
    main()

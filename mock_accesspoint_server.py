#!/usr/bin/env python3
"""
Mock gamexp accesspoint API server
Intercepts requests from launchpoint.exe and returns valid responses
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

class MockAccessPointHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/app':
            # Return valid game configuration
            response = {
                "game_state_hint_0": "Game supported",
            }
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        print(f"[MOCK SERVER] {args[0]}")

if __name__ == '__main__':
    print("Starting mock accesspoint API server on port 8443...")
    server = HTTPServer(('127.0.0.1', 8443), MockAccessPointHandler)
    print("Server running! Intercepting requests from launchpoint.exe")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down mock server...")
        server.shutdown()

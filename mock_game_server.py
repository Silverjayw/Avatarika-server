#!/usr/bin/env python3
"""
Mock Game Server for AVATARIKA Game
Handles game protocol connections on port 25858.

Protocol:
- 4-byte header: [Type][Sub-type][Reserved]
- Variable payload (25-byte messages common)
- Types: 0x01 (keepalive), 0x02 (data), 0x05 (extended), 0x0d/0x0e (ACK), 0x19 (events)
"""

import socket
import struct
import time
import threading
from datetime import datetime

KEEPALIVE_INTERVAL = 10
HEARTBEAT_MESSAGE = b'\x02\x01\x00\x00\x00' * 5  # 25 bytes of keepalive data

class MockGameServer:
    def __init__(self, host='127.0.0.1', port=25858):
        self.host = host
        self.port = port
        self.clients = {}
        self.client_id = 0
        self.running = False

    def start(self):
        """Start the mock game server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        print(f"Mock Game Server started on {self.host}:{self.port}")
        print(f"  Protocol: Binary (4-byte header + payload)")
        print(f"  Types: 0x01=keepalive, 0x02=data, 0x05=extended, 0x0d=ACK, 0x0e=ACK, 0x19=events")
        print()

        while self.running:
            try:
                client, addr = self.server_socket.accept()
                print(f"Client connected: {addr}")
                client_id = self.handle_client(client, addr)
                self.clients[client_id] = client
                print(f"Client {client_id} connected")
            except OSError as e:
                if self.running:
                    print(f"Error accepting connection: {e}")
                else:
                    break
            except Exception as e:
                print(f"Error: {e}")

    def stop(self):
        """Stop the mock game server"""
        self.running = False
        self.server_socket.close()
        print("\nServer stopped")

    def handle_client(self, client, addr):
        """Handle a client connection"""
        client_id = self.client_id
        self.client_id += 1
        print(f"\n=== CLIENT {client_id} ({addr}) ===")

        try:
            while self.running:
                data = client.recv(1024)
                if not data:
                    break

                print(f"  Received {len(data)} bytes")
                self.process_message(client, addr, data, client_id)

                # Send keepalive response
                response = struct.pack('I', 0x01) + struct.pack('I', 0x00) + HEARTBEAT_MESSAGE
                client.sendall(response)
                print(f"  Sent keepalive response")

        except ConnectionResetError:
            print(f"  Client {client_id} disconnected")
        except Exception as e:
            print(f"  Error handling client {client_id}: {e}")
        finally:
            client.close()
            print(f"  Client {client_id} connection closed")

        return client_id

    def process_message(self, client, addr, data, client_id):
        """Process incoming message"""
        if len(data) < 4:
            print(f"  [WARN] Message too short: {len(data)} bytes")
            return

        msg_type = data[0]
        sub_type = data[1]
        reserved = data[2:4]
        payload = data[4:]

        print(f"  Type: 0x{msg_type:02x}, SubType: 0x{sub_type:02x}, Payload: {len(payload)} bytes")

        # Log message
        timestamp = datetime.now().strftime('%H:%M:%S.%f')
        print(f"  [{timestamp}] {client_id}: type=0x{msg_type:02x} sub=0x{sub_type:02x} len={len(payload)}")

    def send_to_all(self, msg_type, sub_type, data=b''):
        """Send message to all connected clients"""
        message = struct.pack('II', msg_type, sub_type) + data
        for client_id, client in self.clients.items():
            try:
                client.sendall(message)
            except:
                pass

if __name__ == '__main__':
    server = MockGameServer()
    server.start()

    # Handle shutdown
    def shutdown():
        server.stop()

    try:
        import signal
        signal.signal(signal.SIGINT, lambda s, f: shutdown())
        signal.signal(signal.SIGTERM, lambda s, f: shutdown())
        input("\nPress Enter to stop the server...")
        shutdown()
    except KeyboardInterrupt:
        shutdown()

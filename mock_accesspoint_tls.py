#!/usr/bin/env python3
"""
Mock Gamexp Accesspoint TLS server
TLS 1.3 on 127.0.0.1:27018 with custom record type 0x17
SNI: *.gamexp.com
"""

import ssl
import socket
import struct
import logging
import os
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Generate self-signed certificate for *.gamexp.com
CERT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_PATH = os.path.join(CERT_DIR, 'accesspoint_server.crt')
KEY_PATH = os.path.join(CERT_DIR, 'accesspoint_server.key')

def generate_cert():
    """Generate self-signed TLS certificate"""
    logger.info("Generating self-signed certificate for *.gamexp.com...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "*.gamexp.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mock Accesspoint"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before()
        .not_valid_after(x509.RelativeTime(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("*.gamexp.com"),
                x509.DNSName("accesspoint-api.gamexp.com"),
                x509.IPAddress(socket.inet_aton("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(CERT_PATH, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(KEY_PATH, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    logger.info("Certificate saved to %s and %s", CERT_PATH, KEY_PATH)
    return CERT_PATH, KEY_PATH

def build_0x17_record(sub_type, payload):
    """Build custom 0x17 TLS record"""
    # Header: [type:1][length:3][sub_type:1][length:2]
    header = struct.pack('!BHIHB', 0x17, len(payload), sub_type, len(payload))
    return header + payload

def parse_0x17_record(data):
    """Parse custom 0x17 record header"""
    if len(data) < 7:
        return None, data
    rec_type, length, sub_type, payload_len = struct.unpack('!BHIHB', data[:7])
    if rec_type != 0x17:
        return None, data
    if len(data) < 7 + payload_len:
        return None, data
    payload = data[7:7 + payload_len]
    return {
        'type': rec_type,
        'length': length,
        'sub_type': sub_type,
        'payload_len': payload_len,
        'payload': payload,
    }, data[7 + payload_len:]

# Sub-types we know about from the binary protocol
SUB_TYPE_ACK = 0x00
SUB_TYPE_EVENTS = 0x01
SUB_TYPE_KEEPALIVE = 0x02

class MockAccesspointHandler:
    def __init__(self, conn):
        self.conn = conn
        self.peer = conn.getpeername()
        self.server_name = conn.getservername()

    def handle(self):
        logger.info("Client connected: %s (SNI=%s)", self.peer, self.server_name)

        try:
            # Read until we get a complete 0x17 record
            # The client should send something after TLS handshake
            buffer = b''
            while True:
                data = self.conn.recv(65536)
                if not data:
                    logger.info("Client disconnected")
                    return

                if self.server_name == "127.0.0.1":
                    logger.info("Raw TLS data received: %d bytes", len(data))
                    buffer += data

                    # Try to parse as 0x17 record
                    record, remaining = parse_0x17_record(buffer)
                    buffer = remaining

                    if record:
                        logger.info("Received 0x17 record: sub_type=0x%02x, payload=%d bytes",
                                  record['sub_type'], record['payload_len'])

                        # Log the raw payload for analysis
                        payload_hex = record['payload'][:64].hex()
                        logger.info("Payload hex: %s...", payload_hex)

                        # Send ACK response
                        ack_payload = struct.pack('!B', SUB_TYPE_ACK)
                        ack_record = build_0x17_record(SUB_TYPE_ACK, ack_payload)
                        self.conn.sendall(ack_record)
                        logger.info("Sent ACK response (sub_type=0x%02x)", SUB_TYPE_ACK)
                        return

            logger.error("Unexpected disconnection")
        except Exception as e:
            logger.error("Error handling client: %s", e)
        finally:
            try:
                self.conn.close()
            except:
                pass

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Mock Gamexp Accesspoint TLS Server')
    parser.add_argument('--port', type=int, default=27018, help='Port to listen on (default: 27018)')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--cert', type=str, default=CERT_PATH, help='Path to TLS certificate')
    parser.add_argument('--key', type=str, default=KEY_PATH, help='Path to TLS key')
    parser.add_argument('--generate-cert', action='store_true', help='Generate self-signed certificate')
    args = parser.parse_args()

    if args.generate_cert:
        generate_cert()
        return

    if not os.path.exists(args.cert) or not os.path.exists(args.key):
        logger.info("Certificate not found, generating...")
        generate_cert()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(5)
    logger.info("Mock accesspoint server listening on %s:%d", args.host, args.port)
    logger.info("Waiting for client connection...")

    try:
        while True:
            conn, addr = server.accept()
            conn.settimeout(30)
            handler = MockAccesspointHandler(conn)
            try:
                handler.handle()
            except ssl.SSLError as e:
                logger.error("SSL error from %s: %s", addr, e)
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    conn.close()
                except:
                    pass
            except socket.timeout:
                logger.info("Client timed out, disconnecting")
                try:
                    conn.close()
                except:
                    pass
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.close()

if __name__ == '__main__':
    main()

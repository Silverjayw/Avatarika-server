#!/usr/bin/env python3
"""
AVATARIKA Protocol Analyzer
Analyzes the game network protocol based on packet capture analysis
"""

import struct
import json
from collections import defaultdict
from scapy.all import rdpcap, TCP, IP

class ProtocolAnalyzer:
    def __init__(self, pcap_path):
        self.packets = rdpcap(pcap_path)
        self.conn_data = self._extract_connections()
        self.protocol_types = {}
        
    def _extract_connections(self):
        """Extract all TCP connections with data"""
        conn_data = {}
        for pkt in self.packets:
            if IP in pkt and TCP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                if src == '127.0.0.1' and dst == '127.0.0.1':
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    key = f'{sport}->{dport}'
                    payload = bytes(pkt[TCP].payload)
                    if payload and len(payload) >= 4:
                        if key not in conn_data:
                            conn_data[key] = []
                        conn_data[key].append({
                            'direction': 'client->server' if sport > dport else 'server->client',
                            'payload': payload,
                            'length': len(payload)
                        })
        return conn_data
    
    def analyze_protocol(self):
        """Analyze the binary protocol"""
        print("=" * 80)
        print("AVATARIKA PROTOCOL ANALYSIS")
        print("=" * 80)
        print()
        
        # Analyze keepalive protocol (0x01)
        print("1. KEEPALIVE PROTOCOL (Type 0x01)")
        print("-" * 40)
        if '38560->57343' in self.conn_data:
            pkts = self.conn_data['38560->57343']
            keepalive_count = sum(1 for p in pkts if len(p['payload']) == 4 and p['payload'][0] == 0x01)
            print(f"   - Messages: {keepalive_count}")
            print(f"   - Format: 4-byte header (0x01000000)")
            print(f"   - Purpose: Connection keepalive/heartbeat")
            print(f"   - Interval: ~1 second")
            print()
        
        # Analyze 25-byte protocol messages (Type 0x02)
        print("2. DATA MESSAGES (Type 0x02)")
        print("-" * 40)
        if '57343->38560' in self.conn_data:
            pkts = self.conn_data['57343->38560']
            data_count = sum(1 for p in pkts if len(p['payload']) == 25 and p['payload'][0] == 0x02)
            print(f"   - Messages: {data_count}")
            print(f"   - Format: 25-byte structured message")
            print(f"   - Structure:")
            print(f"     Byte 0:  0x02 (message type)")
            print(f"     Byte 1:  0x01 (sub_type)")
            print(f"     Bytes 2-4: 0x000000 (reserved)")
            print(f"     Bytes 5-7: Timestamp or sequence counter")
            print(f"     Byte 8:  0x00 (reserved)")
            print(f"     Bytes 9-12: Length field (0x0c = 12)")
            print(f"     Bytes 13-16: Version or flags (0x01000000)")
            print(f"     Bytes 17-24: Data or padding")
            print(f"   - Purpose: Game data transfer")
            print()
        
        # Analyze extended messages (Type 0x19)
        print("3. EXTENDED MESSAGES (Type 0x19)")
        print("-" * 40)
        if '57343->38560' in self.conn_data:
            pkts = self.conn_data['57343->38560']
            ext_count = sum(1 for p in pkts if len(p['payload']) >= 4 and p['payload'][0] == 0x19)
            print(f"   - Messages: {ext_count}")
            print(f"   - Format: Variable length (header + payload)")
            print(f"   - Structure:")
            print(f"     Byte 0:  0x19 (message type)")
            print(f"     Bytes 1-3: Length field")
            print(f"     Payload: Variable data")
            print(f"   - Purpose: Extended game events")
            print()
        
        # Analyze 4-byte messages (Type 0x0d, 0x0e)
        print("4. ACKNOWLEDGMENT MESSAGES (Type 0x0d, 0x0e)")
        print("-" * 40)
        if '57343->38560' in self.conn_data:
            pkts = self.conn_data['57343->38560']
            ack_count = sum(1 for p in pkts if len(p['payload']) == 4 and p['payload'][0] in [0x0d, 0x0e])
            print(f"   - ACK messages (0x0d): {ack_count}")
            print(f"   - ACK messages (0x0e): {ack_count - sum(1 for p in pkts if len(p['payload']) == 4 and p['payload'][0] == 0x0d)}")
            print(f"   - Format: 4-byte header")
            print(f"   - Purpose: Message acknowledgment")
            print()
        
        # Analyze WebSocket events
        print("5. GAME RECORDING EVENTS (WebSocket)")
        print("-" * 40)
        if '41975->60406' in self.conn_data:
            pkts = self.conn_data['41975->60406']
            print(f"   - Messages: {len(pkts)}")
            print(f"   - Format: Binary WebSocket frames")
            print(f"   - Content: GameRecording.NotifyTimelineChanged")
            print(f"   - Purpose: Game state recording")
            print()
        
        # Health check endpoint
        print("6. HEALTH CHECK ENDPOINT (Port 33207)")
        print("-" * 40)
        print(f"   - URL: GET /global/health")
        print(f"   - Response: JSON")
        print(f"   - Format: {{\"healthy\": true, \"version\": \"local\"}}")
        print(f"   - Purpose: Server health monitoring")
        print()
        
        # Protocol summary
        print("=" * 80)
        print("PROTOCOL SUMMARY")
        print("=" * 80)
        print()
        print("Connection Flow:")
        print("  Client -> Server: 25-byte messages (Type 0x02)")
        print("  Server -> Client: 4-byte ACKs (Type 0x0d/0x0e)")
        print("  Both: 4-byte keepalive (Type 0x01)")
        print()
        print("Message Types:")
        print("  0x01: Keepalive/Heartbeat")
        print("  0x02: Data message (25 bytes)")
        print("  0x05: Extended data")
        print("  0x0d: Acknowledgment")
        print("  0x0e: Acknowledgment")
        print("  0x19: Extended event")
        print()
        print("Server Requirements:")
        print("  1. Health check endpoint (HTTP/JSON)")
        print("  2. Binary protocol server (ports 25858, 25859, 25868)")
        print("  3. WebSocket support for game recording")
        print("  4. Authentication system (HMAC-SHA256)")
        print()

def main():
    analyzer = ProtocolAnalyzer('/home/sanitar/Desktop/AVATARIKA/avatarika.pcapng')
    analyzer.analyze_protocol()

if __name__ == '__main__':
    main()

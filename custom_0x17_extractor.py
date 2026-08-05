#!/usr/bin/env python3
"""
AVATARIKA Custom 0x17 Record Extractor
Extracts and decodes binary protocol messages from custom TLS record type 0x17
"""

import struct
from scapy.all import rdpcap, IP, TCP

def parse_custom_0x17(pcap_path):
    """Extract all custom 0x17 records from the pcap"""
    packets = rdpcap(pcap_path)
    
    print("=" * 80)
    print("AVATARIKA CUSTOM 0x17 RECORD EXTRACTOR")
    print("=" * 80)
    print()
    
    # Collect all 0x17 records
    records = []
    for i, pkt in enumerate(packets):
        if IP in pkt and TCP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            
            if pkt[TCP].payload:
                data = bytes(pkt[TCP].payload)
                offset = 0
                
                while offset < len(data) - 5:
                    if offset + 5 > len(data):
                        break
                    
                    record_type = data[offset]
                    length = struct.unpack('>H', data[offset+1:offset+3])[0]
                    payload = data[offset+4:offset+4+length] if offset + 4 + length <= len(data) else data[offset+4:]
                    
                    if record_type == 0x17 and len(payload) > 0:
                        records.append({
                            'index': i,
                            'src': src,
                            'dst': dst,
                            'sport': sport,
                            'dport': dport,
                            'payload': payload,
                            'payload_hex': payload.hex(),
                            'payload_len': len(payload)
                        })
                    
                    offset += 4 + length
    
    # Group by connection
    conn_records = {}
    for r in records:
        key = f'{r["src"]}:{r["sport"]} -> {r["dst"]}:{r["dport"]}'
        if key not in conn_records:
            conn_records[key] = []
        conn_records[key].append(r)
    
    # Print summary
    print(f"Total custom 0x17 records: {len(records)}")
    print()
    
    for conn, recs in sorted(conn_records.items()):
        print(f"Connection: {conn}")
        print(f"  Records: {len(recs)}")
        for r in recs[:5]:  # Show first 5
            print(f"  [{r['index']}] {r['payload_len']} bytes: {r['payload_hex'][:60]}...")
        if len(recs) > 5:
            print(f"  ... and {len(recs) - 5} more")
        print()
    
    # Focus on the game server connection (27018)
    print("=" * 80)
    print("GAME SERVER CONNECTION (205.196.6.132:27018)")
    print("=" * 80)
    print()
    
    if '205.196.6.132:27018 -> 10.0.0.9:46133' in conn_records:
        print("Server -> Client:")
        for r in conn_records['205.196.6.132:27018 -> 10.0.0.9:46133']:
            payload = r['payload']
            print(f"  [{r['index']}] {r['payload_len']} bytes")
            print(f"    Hex: {payload.hex()}")
            # Try to decode as binary protocol
            if len(payload) >= 4:
                msg_type = payload[0]
                length = struct.unpack('>H', payload[1:3])[0] if len(payload) >= 3 else 0
                print(f"    Type: 0x{msg_type:02x} (0x10 = keepalive), Length: {length}")
            print()
    
    if '10.0.0.9:46133 -> 205.196.6.132:27018' in conn_records:
        print("Client -> Server:")
        for r in conn_records['10.0.0.9:46133 -> 205.196.6.132:27018']:
            payload = r['payload']
            print(f"  [{r['index']}] {r['payload_len']} bytes")
            print(f"    Hex: {payload.hex()}")
            # Try to decode as binary protocol
            if len(payload) >= 4:
                msg_type = payload[0]
                length = struct.unpack('>H', payload[1:3])[0] if len(payload) >= 3 else 0
                print(f"    Type: 0x{msg_type:02x} (0x10 = keepalive), Length: {length}")
            print()
    
    # Focus on the main API connection (162.159.135.232:443)
    print("=" * 80)
    print("MAIN API CONNECTION (162.159.135.232:443)")
    print("=" * 80)
    print()
    
    if '10.0.0.9:60980 -> 162.159.135.232:443' in conn_records:
        print("Client -> Server:")
        for r in conn_records['10.0.0.9:60980 -> 162.159.135.232:443']:
            payload = r['payload']
            print(f"  [{r['index']}] {r['payload_len']} bytes")
            print(f"    Hex: {payload.hex()}")
            if len(payload) >= 4:
                msg_type = payload[0]
                length = struct.unpack('>H', payload[1:3])[0] if len(payload) >= 3 else 0
                print(f"    Type: 0x{msg_type:02x}, Length: {length}")
            print()
    
    # Focus on auth connection (162.159.130.235:8443)
    print("=" * 80)
    print("AUTH CONNECTION (162.159.130.235:8443)")
    print("=" * 80)
    print()
    
    if '10.0.0.9:53118 -> 162.159.130.235:8443' in conn_records:
        print("Client -> Server:")
        for r in conn_records['10.0.0.9:53118 -> 162.159.130.235:8443']:
            payload = r['payload']
            print(f"  [{r['index']}] {r['payload_len']} bytes")
            print(f"    Hex: {payload.hex()}")
            if len(payload) >= 4:
                msg_type = payload[0]
                length = struct.unpack('>H', payload[1:3])[0] if len(payload) >= 3 else 0
                print(f"    Type: 0x{msg_type:02x}, Length: {length}")
            print()
    
    if '162.159.130.235:8443 -> 10.0.0.9:53118' in conn_records:
        print("Server -> Client:")
        for r in conn_records['162.159.130.235:8443 -> 10.0.0.9:53118']:
            payload = r['payload']
            print(f"  [{r['index']}] {r['payload_len']} bytes")
            print(f"    Hex: {payload.hex()}")
            if len(payload) >= 4:
                msg_type = payload[0]
                length = struct.unpack('>H', payload[1:3])[0] if len(payload) >= 3 else 0
                print(f"    Type: 0x{msg_type:02x}, Length: {length}")
            print()
    
    # Show all connections with 0x17 records
    print("=" * 80)
    print("ALL CONNECTIONS WITH 0x17 RECORDS")
    print("=" * 80)
    print()
    
    for conn, recs in sorted(conn_records.items()):
        print(f"Connection: {conn}")
        print(f"  Records: {len(recs)}")
        for r in recs:
            payload = r['payload']
            print(f"  [{r['index']}] {r['payload_len']} bytes")
            print(f"    Hex: {payload[:40].hex()}...")
            if len(payload) >= 4:
                msg_type = payload[0]
                length = struct.unpack('>H', payload[1:3])[0] if len(payload) >= 3 else 0
                print(f"    Type: 0x{msg_type:02x}, Length: {length}")
            print()

if __name__ == '__main__':
    parse_custom_0x17('/home/sanitar/Desktop/AVATARIKA/Avatarika2.pcapng')

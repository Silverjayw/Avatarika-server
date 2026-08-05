#!/usr/bin/env python3
"""
AVATARIKA PCAP Deep Analyzer - avatarika2.pcapng
Manual TLS record parsing (no scapy TLS layer needed)
"""

import struct
import json
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, Raw, DNS

TLS_RECORD_TYPES = {
    0x00: 'ChangeCipherSpec',
    0x01: 'Alert',
    0x02: 'Handshake',
    0x03: 'Application Data',
    0x14: 'Heartbeat',
    0x15: 'Encrypted Extensions',
    0x16: 'NewSessionTicket',
    0x17: 'Unknown (likely custom)',
    0x18: 'Unknown',
    0x19: 'Unknown',
    0x1A: 'Unknown',
    0x1B: 'Unknown',
    0x1C: 'Unknown',
    0x1D: 'Unknown',
    0x1E: 'Unknown',
    0x1F: 'Unknown',
    0x20: 'Unknown',
}

def parse_tls_record(data):
    """Parse TLS wire format record"""
    if len(data) < 5:
        return None
    return {
        'type': TLS_RECORD_TYPES.get(data[0], f'Unknown(0x{data[0]:02x})'),
        'version': f'{data[1]:02x}{data[2]:02x}',
        'length': struct.unpack('>H', data[2:4])[0],
        'payload': data[4:]
    }

def parse_client_hello(payload):
    """Parse TLS ClientHello"""
    result = {
        'version': f'{payload[0]:02x}{payload[1]:02x}',
        'random': payload[2:34].hex(),
        'session_id_length': payload[34],
        'cipher_suites': []
    }
    
    offset = 35
    if offset < len(payload):
        cipher_len = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2
        for i in range(cipher_len // 2):
            if offset + 2 <= len(payload):
                cs = struct.unpack('>H', payload[offset:offset+2])[0]
                result['cipher_suites'].append(cs)
                offset += 2
    
    if offset < len(payload):
        ext_len = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2
        while offset + 4 <= len(payload) and offset + 2 + ext_len <= len(payload):
            ext_type = struct.unpack('>H', payload[offset:offset+2])[0]
            ext_data_len = struct.unpack('>H', payload[offset+2:offset+4])[0]
            ext_data = payload[offset+4:offset+4+ext_data_len]
            
            if ext_type == 0:
                sni_len = struct.unpack('>H', ext_data[1:3])[0]
                result['server_name'] = ext_data[3:3+sni_len].decode('ascii', errors='replace')
            elif ext_type == 10:
                ver_len = struct.unpack('>H', ext_data[1:3])[0]
                result['supported_versions'] = []
                for j in range(ver_len // 2):
                    result['supported_versions'].append(f'{struct.unpack(">H", ext_data[3+j*2:5+j*2])[0]:04x}')
            elif ext_type == 5:
                result['has_session_tickets'] = True
            elif ext_type == 16:
                result['has_ec_point_formats'] = True
                
            offset += 4 + ext_data_len
    
    return result

def parse_server_hello(payload):
    """Parse TLS ServerHello"""
    result = {
        'version': f'{payload[0]:02x}{payload[1]:02x}',
        'random': payload[2:34].hex(),
        'session_id_length': payload[34],
        'cipher_suite': struct.unpack('>H', payload[35:37])[0] if len(payload) > 37 else 0,
        'compression': payload[37] if len(payload) > 37 else 0,
    }
    return result

def analyze_pcap(pcap_path):
    """Main analysis function"""
    packets = rdpcap(pcap_path)
    
    print("=" * 80)
    print("AVATARIKA2 PCAP DEEP ANALYSIS")
    print("=" * 80)
    print()
    
    # 1. Summary
    print("1. PACKET SUMMARY")
    print("-" * 40)
    total = len(packets)
    tcp_count = sum(1 for p in packets if TCP in p)
    ip_count = sum(1 for p in packets if IP in p)
    dns_count = sum(1 for p in packets if DNS in p)
    raw_bytes = 0
    for p in packets:
        raw_bytes += len(bytes(p))
    
    print(f"   Total packets: {total}")
    print(f"   IP packets: {ip_count}")
    print(f"   TCP packets: {tcp_count}")
    print(f"   DNS packets: {dns_count}")
    print(f"   Total raw bytes: {raw_bytes}")
    print()
    
    # 2. Connections
    print("2. CONNECTIONS")
    print("-" * 40)
    connections = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'payloads': []})
    
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            payload = bytes(pkt[TCP].payload) if pkt[TCP].payload else b''
            
            key = f'{src}:{sport} -> {dst}:{dport}'
            connections[key]['packets'] += 1
            connections[key]['bytes'] += len(payload)
            if payload:
                connections[key]['payloads'].append(payload)
    
    for conn, info in sorted(connections.items()):
        print(f"   {conn}")
        print(f"     Packets: {info['packets']}, Bytes: {info['bytes']}")
    print()
    
    # 3. TLS Analysis
    print("3. TLS RECORD ANALYSIS")
    print("-" * 40)
    
    tls_connections = set()
    
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            conn_key = f'{src}:{sport} -> {dst}:{dport}'
            
            if pkt[TCP].payload:
                data = bytes(pkt[TCP].payload)
                offset = 0
                
                while offset < len(data) - 5:
                    if offset + 5 > len(data):
                        break
                    
                    record_type = data[offset]
                    length = struct.unpack('>H', data[offset+1:offset+3])[0]
                    payload = data[offset+4:offset+4+length] if offset + 4 + length <= len(data) else data[offset+4:]
                    
                    type_name = TLS_RECORD_TYPES.get(record_type, f'Unknown(0x{record_type:02x})')
                    
                    if record_type == 0x02 and payload and len(payload) >= 4:
                        msg_type = payload[0]
                        
                        if msg_type == 0x01:  # ClientHello
                            print(f"   [ClientHello] {conn_key}")
                            hello = parse_client_hello(payload)
                            print(f"     Version: {hello['version']}")
                            print(f"     Random: {hello['random'][:16]}...")
                            if hello.get('cipher_suites'):
                                print(f"     Cipher suites: {hello['cipher_suites'][:8]}")
                            if hello.get('server_name'):
                                print(f"     SNI: {hello['server_name']}")
                            if hello.get('supported_versions'):
                                print(f"     Supported versions: {hello['supported_versions'][:5]}")
                            if hello.get('session_id_length'):
                                print(f"     Session ID length: {hello['session_id_length']}")
                            print(f"     Payload length: {len(payload)} bytes")
                        
                        elif msg_type == 0x02:  # ServerHello
                            print(f"   [ServerHello] {conn_key}")
                            hello = parse_server_hello(payload)
                            print(f"     Version: {hello['version']}")
                            print(f"     Random: {hello['random'][:16]}...")
                            print(f"     Cipher suite: 0x{hello['cipher_suite']:04x}")
                            print(f"     Compression: {hello['compression']}")
                            print(f"     Payload length: {len(payload)} bytes")
                        
                        elif msg_type == 0x03:  # Certificate
                            print(f"   [Certificate] {conn_key} ({len(payload)} bytes)")
                        
                        elif msg_type == 0x13:  # NewSessionTicket
                            print(f"   [NewSessionTicket] {conn_key} ({len(payload)} bytes)")
                        
                        elif msg_type == 0x0a:  # CertificateVerify
                            print(f"   [CertificateVerify] {conn_key}")
                        
                        elif msg_type == 0x14:  # ClientKeyExchange
                            print(f"   [ClientKeyExchange] {conn_key} ({len(payload)} bytes)")
                            if payload:
                                print(f"     Hex: {payload[:40].hex()}")
                        
                        elif msg_type == 0x07:  # ServerKeyExchange
                            print(f"   [ServerKeyExchange] {conn_key} ({len(payload)} bytes)")
                            if payload:
                                print(f"     Hex: {payload[:40].hex()}")
                        
                        elif msg_type == 0x08:  # CertificateRequest
                            print(f"   [CertificateRequest] {conn_key} ({len(payload)} bytes)")
                        
                        elif msg_type == 0x15:  # CertificateStatus
                            print(f"   [CertificateStatus] {conn_key}")
                        
                        else:
                            print(f"   [Handshake 0x{msg_type:02x}] {conn_key} ({len(payload)} bytes)")
                            if len(payload) < 200:
                                print(f"     Hex: {payload.hex()}")
                    
                    elif record_type == 0x03 and payload:
                        # Application data
                        if len(payload) > 20:
                            print(f"   [AppData {len(payload)}B] {conn_key}")
                            print(f"     Hex: {payload[:100].hex()}")
                            if len(payload) > 100:
                                print(f"     ... ({len(payload) - 100} more bytes)")
                    
                    elif record_type == 0x17:
                        # Custom record type 0x17!
                        print(f"   [Custom 0x17] {conn_key} ({len(payload)} bytes)")
                        print(f"     Version: {data[offset+1:offset+3].hex()}")
                        print(f"     Payload hex: {payload[:200].hex()}")
                        if len(payload) > 200:
                            print(f"     ... ({len(payload) - 200} more bytes)")
                    
                    offset += 4 + length
                    
                    if offset > len(data):
                        break
    
    print()
    
    # 4. TLS record type distribution by connection
    print("4. TLS RECORD TYPE DISTRIBUTION")
    print("-" * 40)
    
    tls_by_conn = defaultdict(lambda: defaultdict(int))
    
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            conn_key = f'{src}:{sport} -> {dst}:{dport}'
            
            if pkt[TCP].payload:
                data = bytes(pkt[TCP].payload)
                offset = 0
                
                while offset < len(data) - 5:
                    if offset + 5 > len(data):
                        break
                    
                    record_type = data[offset]
                    length = struct.unpack('>H', data[offset+1:offset+3])[0]
                    
                    if offset + 4 + length <= len(data):
                        tls_by_conn[conn_key][record_type] += 1
                    
                    offset += 4 + length
    
    for conn, records in sorted(tls_by_conn.items()):
        print(f"   {conn}")
        for rtype, count in sorted(records.items()):
            type_name = TLS_RECORD_TYPES.get(rtype, f'Unknown(0x{rtype:02x})')
            print(f"     {type_name}: {count}")
    
    print()
    
    # 5. Application data deep analysis
    print("5. APPLICATION DATA (POST-TLS)")
    print("-" * 40)
    
    for pkt in packets:
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
                    
                    if record_type == 0x03 and payload:
                        if len(payload) > 10:
                            print(f"   App data ({len(payload)} bytes) {src}:{sport} -> {dst}:{dport}")
                            print(f"     Hex: {payload[:120].hex()}")
                            if len(payload) > 120:
                                print(f"     ... ({len(payload) - 120} more bytes)")
                            print()
                    
                    offset += 4 + length
    
    print("Analysis complete.")

if __name__ == '__main__':
    analyze_pcap('/home/sanitar/Desktop/AVATARIKA/Avatarika2.pcapng')

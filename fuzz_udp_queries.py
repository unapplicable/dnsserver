#!/usr/bin/env python3
"""
DNS UDP Query Fuzzer
Generates random/malformed DNS queries to test server robustness
"""

import socket
import struct
import random
import time
import sys

SERVER_IP = "127.0.0.1"
SERVER_PORT = 15353

def create_valid_dns_query(domain="test.example.com", qtype=1):
    """Create a valid DNS query packet"""
    # Transaction ID
    txid = random.randint(0, 65535)
    
    # Flags: Standard query, recursion desired
    flags = 0x0100
    
    # Counts
    qdcount = 1  # 1 question
    ancount = 0
    nscount = 0
    arcount = 0
    
    # Header
    header = struct.pack('!HHHHHH', txid, flags, qdcount, ancount, nscount, arcount)
    
    # Question section
    question = b''
    for label in domain.split('.'):
        question += struct.pack('!B', len(label)) + label.encode()
    question += b'\x00'  # End of name
    question += struct.pack('!HH', qtype, 1)  # Type and Class (IN)
    
    return header + question

def create_malformed_packet(strategy):
    """Create various types of malformed packets"""
    
    if strategy == "empty":
        return b''
    
    elif strategy == "short_header":
        # Header too short (less than 12 bytes)
        return struct.pack('!HH', random.randint(0, 65535), 0x0100)
    
    elif strategy == "truncated_header":
        # Partial header
        return struct.pack('!HHH', random.randint(0, 65535), 0x0100, 1)
    
    elif strategy == "invalid_counts":
        # Valid header but impossible question counts
        txid = random.randint(0, 65535)
        flags = 0x0100
        return struct.pack('!HHHHHH', txid, flags, 65535, 65535, 65535, 65535)
    
    elif strategy == "garbage":
        # Random garbage
        length = random.randint(1, 512)
        return bytes(random.randint(0, 255) for _ in range(length))
    
    elif strategy == "null_bytes":
        # All null bytes
        return b'\x00' * random.randint(12, 100)
    
    elif strategy == "oversized":
        # Maximum UDP packet size
        return b'\xff' * 65507
    
    elif strategy == "label_overflow":
        # DNS name with invalid label length
        txid = random.randint(0, 65535)
        flags = 0x0100
        header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
        # Label claiming to be 255 bytes but isn't
        bad_name = struct.pack('!B', 255) + b'A' * 10 + b'\x00'
        question = bad_name + struct.pack('!HH', 1, 1)
        return header + question
    
    elif strategy == "compression_loop":
        # DNS name compression pointer loop
        txid = random.randint(0, 65535)
        flags = 0x0100
        header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
        # Pointer that points to itself
        bad_name = b'\xc0\x0c\x00'  # Pointer to offset 12 (start of name)
        question = bad_name + struct.pack('!HH', 1, 1)
        return header + question
    
    elif strategy == "missing_question":
        # Says it has questions but doesn't
        txid = random.randint(0, 65535)
        flags = 0x0100
        return struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
    
    elif strategy == "invalid_qtype":
        # Valid query but with weird qtype
        query = create_valid_dns_query("test.zone1.test", qtype=65535)
        return query
    
    elif strategy == "long_label":
        # Single label claiming to be > 63 bytes (max per label)
        txid = random.randint(0, 65535)
        flags = 0x0100
        header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
        bad_name = struct.pack('!B', 100) + b'A' * 100 + b'\x00'
        question = bad_name + struct.pack('!HH', 1, 1)
        return header + question
    
    elif strategy == "name_too_long":
        # DNS name > 255 bytes total
        txid = random.randint(0, 65535)
        flags = 0x0100
        header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
        # Create many 63-byte labels
        bad_name = b''
        for i in range(5):
            bad_name += struct.pack('!B', 63) + b'A' * 63
        bad_name += b'\x00'
        question = bad_name + struct.pack('!HH', 1, 1)
        return header + question
    
    elif strategy == "negative_length":
        # Try to cause integer underflow
        txid = random.randint(0, 65535)
        flags = 0x0100
        header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
        bad_name = b'\xff' + b'A' * 10 + b'\x00'  # 0xFF = -1 or 255
        question = bad_name + struct.pack('!HH', 1, 1)
        return header + question
    
    else:
        # Default: valid query
        return create_valid_dns_query("test.zone1.test")

def send_packet(sock, packet, label):
    """Send a packet and handle errors"""
    try:
        sock.sendto(packet, (SERVER_IP, SERVER_PORT))
        print(f"✓ Sent {label:20s} ({len(packet):4d} bytes)")
        return True
    except Exception as e:
        print(f"✗ Error sending {label}: {e}")
        return False

def check_server_alive():
    """Check if server is still responding"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        
        # Send valid query
        query = create_valid_dns_query("host1.zone1.test", qtype=1)
        sock.sendto(query, (SERVER_IP, SERVER_PORT))
        
        # Try to receive response
        data, addr = sock.recvfrom(4096)
        sock.close()
        
        if len(data) > 0:
            return True
        return False
    except socket.timeout:
        return False
    except Exception as e:
        print(f"Error checking server: {e}")
        return False

def main():
    print("=" * 70)
    print("DNS UDP Query Fuzzer - Testing Server Robustness")
    print("=" * 70)
    print(f"Target: {SERVER_IP}:{SERVER_PORT}")
    print()
    
    strategies = [
        "valid_query",
        "empty",
        "short_header",
        "truncated_header",
        "invalid_counts",
        "garbage",
        "null_bytes",
        "oversized",
        "label_overflow",
        "compression_loop",
        "missing_question",
        "invalid_qtype",
        "long_label",
        "name_too_long",
        "negative_length"
    ]
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    
    print("[Phase 1] Testing each attack strategy once...")
    print("-" * 70)
    
    for strategy in strategies:
        if strategy == "valid_query":
            packet = create_valid_dns_query("host1.zone1.test", qtype=1)
        else:
            packet = create_malformed_packet(strategy)
        
        send_packet(sock, packet, strategy)
        time.sleep(0.05)  # Small delay between packets
    
    print()
    print("[Phase 2] Checking if server is still alive...")
    print("-" * 70)
    
    if check_server_alive():
        print("✓ Server is ALIVE and responding to valid queries")
    else:
        print("✗ Server appears to be DOWN or not responding")
        sys.exit(1)
    
    print()
    print("[Phase 3] Random fuzzing (100 packets)...")
    print("-" * 70)
    
    for i in range(100):
        strategy = random.choice(strategies)
        
        if strategy == "valid_query":
            # Mix in some valid queries
            domains = ["host1.zone1.test", "ns1.zone1.test", "invalid.zone1.test", 
                      "test.example.com", "x" * 50 + ".zone1.test"]
            qtypes = [1, 2, 5, 15, 16, 28, 255]  # A, NS, CNAME, MX, TXT, AAAA, ANY
            packet = create_valid_dns_query(random.choice(domains), random.choice(qtypes))
        else:
            packet = create_malformed_packet(strategy)
        
        if i % 10 == 0:
            print(f"Progress: {i}/100 packets sent")
        
        sock.sendto(packet, (SERVER_IP, SERVER_PORT))
        time.sleep(0.02)  # Don't flood
    
    print()
    print("[Phase 4] Final server health check...")
    print("-" * 70)
    
    time.sleep(0.5)
    
    if check_server_alive():
        print("✓ Server survived fuzzing! Still responding to valid queries")
        print()
        print("=" * 70)
        print("RESULT: Server is ROBUST - No crash detected")
        print("=" * 70)
    else:
        print("✗ Server is DOWN after fuzzing")
        print()
        print("=" * 70)
        print("RESULT: Server CRASHED or became unresponsive")
        print("=" * 70)
        sys.exit(1)
    
    sock.close()

if __name__ == "__main__":
    main()

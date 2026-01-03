#!/usr/bin/env python3
"""
Targeted DNS fuzzer to isolate crash-causing packets
Tests one attack at a time with server health checks
"""

import socket
import struct
import random
import time
import subprocess
import sys

SERVER_IP = "127.0.0.1"
SERVER_PORT = 15353

def create_malformed_packet(strategy):
    """Create malformed packet based on strategy"""
    
    if strategy == "null_bytes_large":
        return b'\x00' * 512
    
    elif strategy == "oversized_max":
        # Maximum UDP packet (65507 bytes)
        return b'\xff' * 65507
    
    elif strategy == "oversized_medium":
        return b'\xff' * 10000
    
    elif strategy == "compression_loop":
        # DNS name compression pointer loop
        txid = random.randint(0, 65535)
        flags = 0x0100
        header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
        bad_name = b'\xc0\x0c\x00'  # Pointer to offset 12 (itself)
        question = bad_name + struct.pack('!HH', 1, 1)
        return header + question
    
    elif strategy == "compression_loop_chain":
        # Multiple compression pointers pointing to each other
        txid = random.randint(0, 65535)
        flags = 0x0100
        header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
        # Pointer at offset 12 points to offset 14, which points back to 12
        bad_name = b'\xc0\x0e\xc0\x0c\x00'
        question = bad_name + struct.pack('!HH', 1, 1)
        return header + question
    
    elif strategy == "nested_compression":
        # Valid header with nested compression loops
        txid = random.randint(0, 65535)
        flags = 0x0100
        header = struct.pack('!HHHHHH', txid, flags, 2, 0, 0, 0)
        # Two questions, both with compression loops
        q1 = b'\xc0\x12' + struct.pack('!HH', 1, 1)
        q2 = b'\xc0\x0c' + struct.pack('!HH', 1, 1)
        return header + q1 + q2
    
    elif strategy == "label_count_overflow":
        # Lots of tiny labels to cause counter overflow
        txid = random.randint(0, 65535)
        flags = 0x0100
        header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
        name = b''
        for i in range(250):
            name += b'\x01A'  # Label of length 1 with 'A'
        name += b'\x00'
        question = name + struct.pack('!HH', 1, 1)
        return header + question
    
    elif strategy == "invalid_counts_max":
        txid = random.randint(0, 65535)
        flags = 0x0100
        return struct.pack('!HHHHHH', txid, flags, 65535, 65535, 65535, 65535)
    
    else:
        return b''

def check_server_alive():
    """Check if server responds to valid query"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        
        # Valid query
        txid = random.randint(0, 65535)
        flags = 0x0100
        header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
        
        domain = "host1.zone1.test"
        question = b''
        for label in domain.split('.'):
            question += struct.pack('!B', len(label)) + label.encode()
        question += b'\x00'
        question += struct.pack('!HH', 1, 1)
        
        packet = header + question
        sock.sendto(packet, (SERVER_IP, SERVER_PORT))
        
        data, addr = sock.recvfrom(4096)
        sock.close()
        
        return len(data) > 0
    except:
        return False

def test_attack(strategy, packet):
    """Test a single attack strategy"""
    print(f"\nTesting: {strategy}")
    print(f"  Packet size: {len(packet)} bytes")
    
    # Send attack packet
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    
    try:
        sock.sendto(packet, (SERVER_IP, SERVER_PORT))
        print(f"  ✓ Packet sent")
    except Exception as e:
        print(f"  ✗ Send failed: {e}")
        return True  # Server OK if we couldn't even send
    finally:
        sock.close()
    
    # Wait for server to process
    time.sleep(0.5)
    
    # Check if server still alive
    print(f"  Checking server health...", end='')
    sys.stdout.flush()
    
    if check_server_alive():
        print(" ✓ Server OK")
        return True
    else:
        print(" ✗ SERVER HUNG/CRASHED")
        return False

def main():
    print("=" * 70)
    print("Targeted DNS Fuzzer - Finding the Crash")
    print("=" * 70)
    
    # Check server is running initially
    if not check_server_alive():
        print("ERROR: Server not responding at start")
        sys.exit(1)
    
    print("✓ Server is running and responsive\n")
    
    strategies = [
        "null_bytes_large",
        "compression_loop",
        "compression_loop_chain",
        "nested_compression",
        "label_count_overflow",
        "invalid_counts_max",
        "oversized_medium",
        "oversized_max",
    ]
    
    for strategy in strategies:
        packet = create_malformed_packet(strategy)
        
        if not test_attack(strategy, packet):
            print("\n" + "!" * 70)
            print(f"CULPRIT FOUND: {strategy}")
            print(f"Packet size: {len(packet)} bytes")
            print("!" * 70)
            
            # Show packet hex dump
            print("\nPacket hex dump (first 256 bytes):")
            for i in range(min(256, len(packet))):
                print(f"{packet[i]:02x}", end=' ')
                if (i + 1) % 16 == 0:
                    print()
            print("\n")
            
            sys.exit(1)
    
    print("\n" + "=" * 70)
    print("All tests passed - server survived!")
    print("=" * 70)

if __name__ == "__main__":
    main()

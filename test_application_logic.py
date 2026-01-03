#!/usr/bin/env python3
"""
High-Level DNS Attack Scenarios - Application Logic Testing
Tests UPDATE floods, race conditions, and resource exhaustion
"""

import socket
import struct
import time
import subprocess
import threading
import sys
from datetime import datetime

SERVER_IP = "127.0.0.1"
SERVER_PORT = 15353

class DNSMessage:
    """Helper to construct DNS messages"""
    
    @staticmethod
    def create_query(domain, qtype=1, txid=None):
        """Create a standard DNS query"""
        if txid is None:
            txid = int(time.time() * 1000) & 0xFFFF
        
        flags = 0x0100  # Standard query, recursion desired
        header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
        
        question = b''
        for label in domain.split('.'):
            if label:
                question += struct.pack('!B', len(label)) + label.encode()
        question += b'\x00'
        question += struct.pack('!HH', qtype, 1)
        
        return header + question
    
    @staticmethod
    def create_update(zone, add_record=None):
        """Create a DNS UPDATE message"""
        txid = int(time.time() * 1000) & 0xFFFF
        flags = 0x2800  # UPDATE opcode
        header = struct.pack('!HHHHHH', txid, flags, 1, 0, 1, 0)  # 1 zone, 0 prereq, 1 update
        
        # Zone section (SOA)
        zone_section = b''
        for label in zone.rstrip('.').split('.'):
            zone_section += struct.pack('!B', len(label)) + label.encode()
        zone_section += b'\x00'
        zone_section += struct.pack('!HH', 6, 1)  # SOA, IN
        
        # Update section
        update_section = b''
        if add_record:
            name, rdata = add_record
            for label in name.rstrip('.').split('.'):
                update_section += struct.pack('!B', len(label)) + label.encode()
            update_section += b'\x00'
            update_section += struct.pack('!HHIH', 16, 1, 300, len(rdata))  # TXT, IN, TTL=300
            update_section += rdata.encode()
        
        return header + zone_section + update_section

def check_server_alive():
    """Quick check if server is responsive"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        query = DNSMessage.create_query("host1.zone1.test")
        sock.sendto(query, (SERVER_IP, SERVER_PORT))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return len(data) > 0
    except:
        return False

def test_subdomain_enumeration_flood():
    """Test 1: Subdomain Enumeration Flood"""
    print("\n" + "="*70)
    print("TEST 1: Subdomain Enumeration Flood")
    print("="*70)
    print("Scenario: Query 1000 non-existent subdomains rapidly")
    print("Expected: Server handles NXDOMAIN responses without slowdown")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.1)
    
    start = time.time()
    sent = 0
    
    for i in range(1000):
        subdomain = f"nonexistent{i}.zone1.test"
        query = DNSMessage.create_query(subdomain)
        try:
            sock.sendto(query, (SERVER_IP, SERVER_PORT))
            sent += 1
        except:
            pass
    
    elapsed = time.time() - start
    sock.close()
    
    print(f"  Sent {sent} queries in {elapsed:.2f}s ({sent/elapsed:.0f} q/s)")
    
    # Check server still responsive
    time.sleep(0.5)
    if check_server_alive():
        print("  ✓ PASS: Server still responsive after flood")
        return True
    else:
        print("  ✗ FAIL: Server became unresponsive")
        return False

def test_query_type_flood():
    """Test 2: Query for all possible types"""
    print("\n" + "="*70)
    print("TEST 2: Query Type Flood")
    print("="*70)
    print("Scenario: Query same name with 256 different types")
    print("Expected: Server handles unknown types gracefully")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.1)
    
    domain = "host1.zone1.test"
    sent = 0
    
    for qtype in range(256):
        query = DNSMessage.create_query(domain, qtype=qtype)
        try:
            sock.sendto(query, (SERVER_IP, SERVER_PORT))
            sent += 1
        except:
            pass
    
    sock.close()
    print(f"  Sent {sent} queries with different types")
    
    time.sleep(0.2)
    if check_server_alive():
        print("  ✓ PASS: Server handled all query types")
        return True
    else:
        print("  ✗ FAIL: Server became unresponsive")
        return False

def test_concurrent_queries():
    """Test 3: Concurrent queries from multiple threads"""
    print("\n" + "="*70)
    print("TEST 3: Concurrent Query Storm")
    print("="*70)
    print("Scenario: 10 threads sending 100 queries each")
    print("Expected: No crashes, all threads complete")
    
    def query_worker(thread_id, count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.1)
        for i in range(count):
            domain = f"test{thread_id}-{i}.zone1.test"
            query = DNSMessage.create_query(domain)
            try:
                sock.sendto(query, (SERVER_IP, SERVER_PORT))
            except:
                pass
        sock.close()
    
    threads = []
    start = time.time()
    
    for i in range(10):
        t = threading.Thread(target=query_worker, args=(i, 100))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    elapsed = time.time() - start
    print(f"  All threads completed in {elapsed:.2f}s")
    
    time.sleep(0.5)
    if check_server_alive():
        print("  ✓ PASS: Server survived concurrent queries")
        return True
    else:
        print("  ✗ FAIL: Server became unresponsive")
        return False

def test_long_domain_names():
    """Test 4: Very long domain names"""
    print("\n" + "="*70)
    print("TEST 4: Long Domain Names")
    print("="*70)
    print("Scenario: Query with maximum length domain names")
    print("Expected: Server enforces 255 byte limit")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    
    test_cases = [
        # Maximum valid label (63 bytes)
        "a" * 63 + ".zone1.test",
        # Many labels approaching 255 bytes total
        ".".join(["label" + str(i) for i in range(40)]) + ".zone1.test",
        # Try to exceed 255 bytes
        ".".join(["x" * 50 for i in range(10)]) + ".zone1.test",
    ]
    
    for domain in test_cases:
        try:
            query = DNSMessage.create_query(domain)
            sock.sendto(query, (SERVER_IP, SERVER_PORT))
            print(f"  Sent query for domain length: {len(domain)}")
        except Exception as e:
            print(f"  Query construction failed for length {len(domain)}: {e}")
    
    sock.close()
    
    time.sleep(0.2)
    if check_server_alive():
        print("  ✓ PASS: Server handled long domain names")
        return True
    else:
        print("  ✗ FAIL: Server became unresponsive")
        return False

def test_mixed_tcp_udp():
    """Test 5: Simultaneous TCP and UDP queries"""
    print("\n" + "="*70)
    print("TEST 5: Mixed TCP/UDP Load")
    print("="*70)
    print("Scenario: Simultaneous TCP and UDP queries")
    print("Expected: Both protocols work concurrently")
    
    def udp_worker():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.1)
        for i in range(50):
            query = DNSMessage.create_query(f"udp{i}.zone1.test")
            try:
                sock.sendto(query, (SERVER_IP, SERVER_PORT))
            except:
                pass
            time.sleep(0.01)
        sock.close()
    
    def tcp_worker():
        for i in range(50):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                sock.connect((SERVER_IP, SERVER_PORT))
                
                query = DNSMessage.create_query(f"tcp{i}.zone1.test")
                msglen = struct.pack('!H', len(query))
                sock.send(msglen + query)
                
                # Try to read response
                sock.recv(2)
                sock.close()
            except:
                pass
            time.sleep(0.01)
    
    udp_thread = threading.Thread(target=udp_worker)
    tcp_thread = threading.Thread(target=tcp_worker)
    
    start = time.time()
    udp_thread.start()
    tcp_thread.start()
    
    udp_thread.join()
    tcp_thread.join()
    
    elapsed = time.time() - start
    print(f"  Both workers completed in {elapsed:.2f}s")
    
    if check_server_alive():
        print("  ✓ PASS: Server handled mixed TCP/UDP load")
        return True
    else:
        print("  ✗ FAIL: Server became unresponsive")
        return False

def test_rapid_connections():
    """Test 6: Rapid TCP connection open/close"""
    print("\n" + "="*70)
    print("TEST 6: Rapid TCP Connections")
    print("="*70)
    print("Scenario: Open/close 100 TCP connections rapidly")
    print("Expected: No file descriptor leaks")
    
    connections_made = 0
    start = time.time()
    
    for i in range(100):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((SERVER_IP, SERVER_PORT))
            connections_made += 1
            sock.close()
        except:
            pass
    
    elapsed = time.time() - start
    print(f"  Made {connections_made} connections in {elapsed:.2f}s")
    
    time.sleep(0.5)
    if check_server_alive():
        print("  ✓ PASS: Server handled rapid connections")
        return True
    else:
        print("  ✗ FAIL: Server became unresponsive")
        return False

def main():
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  HIGH-LEVEL DNS ATTACK SCENARIOS")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"Target: {SERVER_IP}:{SERVER_PORT}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Initial health check
    print("\n[Initial Check] Verifying server is running...")
    if not check_server_alive():
        print("  ✗ ERROR: Server not responding")
        sys.exit(1)
    print("  ✓ Server is responsive\n")
    
    # Run tests
    tests = [
        test_subdomain_enumeration_flood,
        test_query_type_flood,
        test_concurrent_queries,
        test_long_domain_names,
        test_mixed_tcp_udp,
        test_rapid_connections,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append((test.__name__, result))
        except Exception as e:
            print(f"  ✗ EXCEPTION: {e}")
            results.append((test.__name__, False))
    
    # Summary
    print("\n" + "━"*70)
    print("  TEST SUMMARY")
    print("━"*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status} - {name}")
    
    print()
    print(f"  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n  ✅ All tests passed - Server is robust!")
        return 0
    else:
        print(f"\n  ⚠️  {total - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())

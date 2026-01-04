#!/usr/bin/env python3
"""
Race Condition & Concurrency Testing
Tests SIGHUP reloads, autosave, and concurrent operations
"""

import socket
import struct
import time
import subprocess
import threading
import signal
import os
import sys
from datetime import datetime

SERVER_IP = "127.0.0.1"
SERVER_PORT = 15353

def send_query(domain):
    """Send a single DNS query"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        
        txid = int(time.time() * 1000) & 0xFFFF
        flags = 0x0100
        header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
        
        question = b''
        for label in domain.split('.'):
            if label:
                question += struct.pack('!B', len(label)) + label.encode()
        question += b'\x00'
        question += struct.pack('!HH', 1, 1)
        
        query = header + question
        sock.sendto(query, (SERVER_IP, SERVER_PORT))
        
        data, _ = sock.recvfrom(4096)
        sock.close()
        return len(data) > 0
    except:
        return False

def test_sighup_during_queries():
    """Test 1: SIGHUP while processing queries"""
    print("\n" + "="*70)
    print("TEST 1: SIGHUP During Active Queries")
    print("="*70)
    print("Scenario: Send SIGHUP while server is processing queries")
    print("Expected: No crashes, graceful reload")
    
    # Get server PID
    try:
        result = subprocess.run(['pgrep', '-f', f'bin/dnsserver.*{SERVER_PORT}'],
                              capture_output=True, text=True)
        server_pid = int(result.stdout.strip())
        print(f"  Server PID: {server_pid}")
    except:
        print("  ✗ ERROR: Could not find server PID")
        return False
    
    # Start query thread
    stop_queries = threading.Event()
    query_count = [0]
    errors = [0]
    
    def query_worker():
        while not stop_queries.is_set():
            if send_query("host1.zone1.test"):
                query_count[0] += 1
            else:
                errors[0] += 1
            time.sleep(0.01)
    
    query_thread = threading.Thread(target=query_worker)
    query_thread.start()
    
    # Let queries run for a bit
    time.sleep(0.5)
    
    # Send SIGHUP
    print("  Sending SIGHUP...")
    try:
        os.kill(server_pid, signal.SIGHUP)
    except Exception as e:
        print(f"  ✗ ERROR sending SIGHUP: {e}")
        stop_queries.set()
        query_thread.join()
        return False
    
    # Continue queries during reload
    time.sleep(1.0)
    
    # Stop queries
    stop_queries.set()
    query_thread.join()
    
    print(f"  Queries: {query_count[0]} successful, {errors[0]} failed")
    
    # Check server still alive
    time.sleep(0.5)
    if send_query("host1.zone1.test"):
        print("  ✓ PASS: Server survived SIGHUP during queries")
        return True
    else:
        print("  ✗ FAIL: Server not responding after SIGHUP")
        return False

def test_rapid_sighups():
    """Test 2: Rapid SIGHUP signals"""
    print("\n" + "="*70)
    print("TEST 2: Rapid SIGHUP Storm")
    print("="*70)
    print("Scenario: Send 10 SIGHUPs rapidly")
    print("Expected: Server handles gracefully, no race conditions")
    
    try:
        result = subprocess.run(['pgrep', '-f', f'bin/dnsserver.*{SERVER_PORT}'],
                              capture_output=True, text=True)
        server_pid = int(result.stdout.strip())
    except:
        print("  ✗ ERROR: Could not find server PID")
        return False
    
    print("  Sending 10 rapid SIGHUPs...")
    for i in range(10):
        try:
            os.kill(server_pid, signal.SIGHUP)
            time.sleep(0.05)
        except:
            print(f"  ✗ ERROR: Signal failed at iteration {i}")
            return False
    
    # Wait for reloads to complete
    time.sleep(2.0)
    
    # Check server
    if send_query("host1.zone1.test"):
        print("  ✓ PASS: Server survived rapid SIGHUPs")
        return True
    else:
        print("  ✗ FAIL: Server not responding")
        return False

def test_concurrent_query_types():
    """Test 3: Concurrent different query types"""
    print("\n" + "="*70)
    print("TEST 3: Concurrent Mixed Query Types")
    print("="*70)
    print("Scenario: A, NS, MX, TXT queries simultaneously")
    print("Expected: All queries handled correctly")
    
    def query_type_worker(qtype, count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.1)
        for i in range(count):
            txid = int(time.time() * 1000) & 0xFFFF
            flags = 0x0100
            header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
            
            domain = "host1.zone1.test"
            question = b''
            for label in domain.split('.'):
                question += struct.pack('!B', len(label)) + label.encode()
            question += b'\x00'
            question += struct.pack('!HH', qtype, 1)
            
            try:
                sock.sendto(header + question, (SERVER_IP, SERVER_PORT))
            except:
                pass
        sock.close()
    
    types = [1, 2, 15, 16]  # A, NS, MX, TXT
    threads = []
    
    start = time.time()
    for qtype in types:
        t = threading.Thread(target=query_type_worker, args=(qtype, 100))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    elapsed = time.time() - start
    print(f"  All query types completed in {elapsed:.2f}s")
    
    if send_query("host1.zone1.test"):
        print("  ✓ PASS: Server handled concurrent query types")
        return True
    else:
        print("  ✗ FAIL: Server not responding")
        return False

def test_tcp_connection_storm():
    """Test 4: Many simultaneous TCP connections"""
    print("\n" + "="*70)
    print("TEST 4: TCP Connection Storm")
    print("="*70)
    print("Scenario: 50 simultaneous TCP connections")
    print("Expected: Server handles or rejects gracefully")
    
    def tcp_query():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((SERVER_IP, SERVER_PORT))
            
            txid = int(time.time() * 1000) & 0xFFFF
            flags = 0x0100
            header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)
            
            domain = "host1.zone1.test"
            question = b''
            for label in domain.split('.'):
                question += struct.pack('!B', len(label)) + label.encode()
            question += b'\x00'
            question += struct.pack('!HH', 1, 1)
            
            query = header + question
            msglen = struct.pack('!H', len(query))
            sock.send(msglen + query)
            
            # Read response
            sock.recv(2)
            sock.close()
            return True
        except:
            return False
    
    threads = []
    start = time.time()
    
    for i in range(50):
        t = threading.Thread(target=tcp_query)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    elapsed = time.time() - start
    print(f"  50 connections completed in {elapsed:.2f}s")
    
    time.sleep(0.5)
    if send_query("host1.zone1.test"):
        print("  ✓ PASS: Server survived TCP storm")
        return True
    else:
        print("  ✗ FAIL: Server not responding")
        return False

def test_query_during_signal():
    """Test 5: Query exactly when SIGHUP arrives"""
    print("\n" + "="*70)
    print("TEST 5: Query During SIGHUP Signal")
    print("="*70)
    print("Scenario: Send query and SIGHUP simultaneously")
    print("Expected: Both handled without crash")
    
    try:
        result = subprocess.run(['pgrep', '-f', f'bin/dnsserver.*{SERVER_PORT}'],
                              capture_output=True, text=True)
        server_pid = int(result.stdout.strip())
    except:
        print("  ✗ ERROR: Could not find server PID")
        return False
    
    # Repeat 10 times
    print("  Testing 10 synchronized query+SIGHUP pairs...")
    for i in range(10):
        # Start query in thread
        query_result = [False]
        def do_query():
            query_result[0] = send_query("host1.zone1.test")
        
        query_thread = threading.Thread(target=do_query)
        query_thread.start()
        
        # Immediately send SIGHUP
        try:
            os.kill(server_pid, signal.SIGHUP)
        except:
            pass
        
        query_thread.join()
        time.sleep(0.2)
    
    # Final check
    if send_query("host1.zone1.test"):
        print("  ✓ PASS: Server handled simultaneous operations")
        return True
    else:
        print("  ✗ FAIL: Server not responding")
        return False

def main():
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  RACE CONDITION & CONCURRENCY TESTING")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"Target: {SERVER_IP}:{SERVER_PORT}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check server is running
    print("\n[Initial Check] Verifying server is running...")
    if not send_query("host1.zone1.test"):
        print("  ✗ ERROR: Server not responding")
        sys.exit(1)
    print("  ✓ Server is responsive\n")
    
    tests = [
        test_sighup_during_queries,
        test_rapid_sighups,
        test_concurrent_query_types,
        test_tcp_connection_storm,
        test_query_during_signal,
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
        print("\n  ✅ All race condition tests passed!")
        return 0
    else:
        print(f"\n  ⚠️  {total - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())

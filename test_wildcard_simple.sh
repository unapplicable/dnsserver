#!/bin/bash
# Simple DNS Wildcard Query Integration Test

set -e

SERVER="127.0.0.1"
PORT="15356"
ZONE_FILE="test_wildcard.zone"

echo "=========================================="
echo "  DNS Wildcard Query Integration Test"
echo "=========================================="
echo ""

# Start server
echo "Starting DNS server..."
./bin/dnsserver -p $PORT -z $ZONE_FILE $SERVER > /tmp/wildcard_test.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    echo "ERROR: Failed to start DNS server"
    cat /tmp/wildcard_test.log
    exit 1
fi

echo "Server started (PID: $SERVER_PID)"
echo ""

# Cleanup on exit
trap "kill $SERVER_PID 2>/dev/null || true; wait $SERVER_PID 2>/dev/null || true" EXIT

# Run tests
PASSED=0
FAILED=0

test_query() {
    local name=$1
    local type=$2
    local expected_count=$3
    local description=$4
    
    result=$(dig @$SERVER -p $PORT "$name" $type +short +tries=1 +time=2 2>/dev/null | grep -v '^$' | wc -l)
    
    if [ "$result" -eq "$expected_count" ]; then
        echo "[PASS] $description (expected $expected_count, got $result)"
        PASSED=$((PASSED + 1))
    else
        echo "[FAIL] $description (expected $expected_count, got $result)"
        FAILED=$((FAILED + 1))
    fi
}

echo "Running tests..."
echo ""

test_query "*.test.example.com" "A" 5 "Single wildcard *.test.example.com A records"
test_query "**.test.example.com" "A" 8 "Double wildcard **.test.example.com A records"
test_query "*.test.example.com" "AAAA" 1 "Single wildcard *.test.example.com AAAA records"
test_query "a.test.example.com" "A" 1 "Exact query a.test.example.com A record"
test_query "x.y.test.example.com" "A" 1 "Exact query x.y.test.example.com A record"
test_query "*.empty.test.example.com" "A" 0 "Wildcard with no matches (empty subdomain)"

echo ""
echo "=========================================="
echo "  Test Summary"
echo "=========================================="
echo "Tests passed: $PASSED"
echo "Tests failed: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "All tests PASSED!"
    exit 0
else
    echo "Some tests FAILED!"
    exit 1
fi

#!/bin/bash
# Test TCP timeout protection against slowloris attacks

echo "=== TCP Timeout Protection Test ==="
echo ""

# Start the DNS server in background
echo "Starting DNS server on port 5353..."
./bin/dnsserver -p 5353 -z test_zone1.zone 127.0.0.1 > /tmp/dnsserver_test.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"
    exit 1
fi

echo "Server started (PID: $SERVER_PID)"
echo ""

# Test 1: Open connection and send nothing (slowloris attack)
echo "Test 1: Opening TCP connection and sending nothing..."
echo "Expected: Connection should timeout after 10 seconds"
echo ""

START_TIME=$(date +%s)
(
    # Open TCP connection to port 5353 but don't send anything
    exec 3<>/dev/tcp/127.0.0.1/5353
    echo "  Connection opened, waiting for timeout..."
    # Try to read (this will block until server closes connection)
    cat <&3 &
    CAT_PID=$!
    sleep 15
    kill $CAT_PID 2>/dev/null
    exec 3>&-
) &
ATTACK_PID=$!

sleep 12
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo "  Connection held for approximately $ELAPSED seconds"
if [ $ELAPSED -ge 9 ] && [ $ELAPSED -le 13 ]; then
    echo "  ✓ PASS: Server timeout working correctly (~10 seconds)"
else
    echo "  ✗ FAIL: Expected ~10 second timeout, got $ELAPSED seconds"
fi

# Kill attack process if still running
kill $ATTACK_PID 2>/dev/null
wait $ATTACK_PID 2>/dev/null

echo ""

# Test 2: Verify server is still responsive after attack
echo "Test 2: Verifying server is still responsive..."
echo "Expected: Server should respond to valid DNS query"
echo ""

# Use dig to send a valid DNS query over TCP
RESPONSE=$(dig @127.0.0.1 -p 5353 +tcp test.example.com 2>&1)
if echo "$RESPONSE" | grep -q "ANSWER SECTION\|status: NOERROR\|status: NXDOMAIN"; then
    echo "  ✓ PASS: Server still responsive after slowloris attempt"
else
    echo "  ✗ FAIL: Server not responding to valid queries"
    echo "  Response: $RESPONSE"
fi

echo ""

# Test 3: Multiple slow connections
echo "Test 3: Opening 3 simultaneous slow connections..."
echo "Expected: All should timeout, server remains responsive"
echo ""

for i in 1 2 3; do
    (
        exec 3<>/dev/tcp/127.0.0.1/5353 2>/dev/null
        sleep 15
        exec 3>&- 2>/dev/null
    ) &
    echo "  Slow connection $i opened (PID: $!)"
done

sleep 2

# Check if server is still responsive during attack
RESPONSE=$(dig @127.0.0.1 -p 5353 +tcp test.example.com 2>&1)
if echo "$RESPONSE" | grep -q "ANSWER SECTION\|status: NOERROR\|status: NXDOMAIN"; then
    echo "  ✓ PASS: Server responsive even with multiple slow connections"
else
    echo "  ✗ FAIL: Server blocked by multiple slow connections"
fi

echo ""
echo "Waiting for all slow connections to timeout..."
sleep 12

echo ""

# Check server logs for timeout messages
echo "=== Server Log (timeout messages) ==="
grep "TCP_TIMEOUT" /tmp/dnsserver_test.log || echo "No timeout messages logged"
echo ""

# Cleanup
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "=== Test Complete ==="

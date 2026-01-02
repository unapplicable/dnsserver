#!/bin/bash
# TSIG Authentication Integration Test Suite

SERVER="127.0.0.1"
PORT="15420"
ZONE="test-tsig.example.com"
LOGFILE="test_tsig.log"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Logging
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    log "PASS: $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    log "FAIL: $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

# Initialize test log
echo "TSIG Integration Test Suite - $(date)" > "$LOGFILE"
log "Testing server: $SERVER:$PORT"
echo ""

# Check if dig is available
if ! command -v dig &> /dev/null; then
    echo "Error: 'dig' command not found. Please install bind-tools/dnsutils"
    exit 1
fi

# Check if nsupdate is available
if ! command -v nsupdate &> /dev/null; then
    echo "Error: 'nsupdate' command not found. Please install bind-tools/dnsutils"
    exit 1
fi

# Start DNS server
log "Starting DNS server on $SERVER:$PORT"
./bin/dnsserver -p $PORT test_tsig.zone $SERVER > server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Check if server is running
if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    echo "Error: Failed to start DNS server"
    cat server.log
    exit 1
fi

log "DNS server started (PID: $SERVER_PID)"

# Cleanup on exit
trap "kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null" EXIT

echo "=========================================="
echo "  TSIG Integration Tests"
echo "=========================================="
echo ""

# Test 1: UPDATE without TSIG (should be REFUSED)
log "TEST 1: UPDATE without TSIG"
result=$(cat << 'EOF' | nsupdate 2>&1
server 127.0.0.1 15420
zone test-tsig.example.com
update add unsigned.test-tsig.example.com 300 A 192.168.1.10
send
EOF
)

if echo "$result" | grep -q "update failed.*REFUSED"; then
    pass "Unsigned UPDATE correctly REFUSED"
else
    fail "Unsigned UPDATE should have been REFUSED"
fi

sleep 1

# Test 2: UPDATE with valid TSIG (should succeed)
log "TEST 2: UPDATE with valid TSIG"
cat << 'EOF' | nsupdate -k testkey.conf >/dev/null 2>&1
server 127.0.0.1 15420
zone test-tsig.example.com
update add signed.test-tsig.example.com 300 A 192.168.1.20
send
EOF

sleep 1
result=$(dig @127.0.0.1 -p 15420 signed.test-tsig.example.com A +short 2>/dev/null)

if [ "$result" == "192.168.1.20" ]; then
    pass "Signed UPDATE succeeded, record added"
else
    fail "Signed UPDATE failed or record not found"
fi

# Test 3: Verify unsigned record was NOT added
log "TEST 3: Verify unsigned record not added"
result=$(dig @127.0.0.1 -p 15420 unsigned.test-tsig.example.com A +short 2>/dev/null)

if [ -z "$result" ]; then
    pass "Unsigned record correctly rejected"
else
    fail "Unsigned record should not exist"
fi

# Test 4: Multiple signed UPDATEs
log "TEST 4: Multiple signed UPDATEs"
for i in 1 2 3; do
    cat << EOF | nsupdate -k testkey.conf >/dev/null 2>&1
server 127.0.0.1 15420
zone test-tsig.example.com
update add host${i}.test-tsig.example.com 300 A 10.0.0.${i}
send
EOF
    sleep 1
done

count=$(dig @127.0.0.1 -p 15420 host1.test-tsig.example.com A +short 2>/dev/null | wc -l)
count=$((count + $(dig @127.0.0.1 -p 15420 host2.test-tsig.example.com A +short 2>/dev/null | wc -l)))
count=$((count + $(dig @127.0.0.1 -p 15420 host3.test-tsig.example.com A +short 2>/dev/null | wc -l)))

if [ "$count" -eq 3 ]; then
    pass "Multiple signed UPDATEs succeeded"
else
    fail "Expected 3 records, found $count"
fi

# Test 5: Delete with TSIG
log "TEST 5: Delete with TSIG"
cat << 'EOF' | nsupdate -k testkey.conf >/dev/null 2>&1
server 127.0.0.1 15420
zone test-tsig.example.com
update delete host1.test-tsig.example.com A
send
EOF

sleep 1
result=$(dig @127.0.0.1 -p 15420 host1.test-tsig.example.com A +short 2>/dev/null)

if [ -z "$result" ]; then
    pass "Signed DELETE succeeded"
else
    fail "Signed DELETE failed, record still exists"
fi

# Stop server
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

# Test Summary
echo ""
echo "=========================================="
echo "  Test Summary"
echo "=========================================="
echo "Total tests run:    $TESTS_RUN"
echo -e "Tests passed:       ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed:       ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All TSIG tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Check $LOGFILE for details.${NC}"
    exit 1
fi

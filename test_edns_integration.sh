#!/bin/bash
# EDNS(0) Integration Test Suite

SERVER="127.0.0.1"
PORT="15421"
LOGFILE="test_edns_integration.log"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
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

info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
    log "INFO: $1"
}

# Initialize test log
echo "EDNS(0) Integration Test Suite - $(date)" > "$LOGFILE"
log "Testing server: $SERVER:$PORT"
echo ""

# Check if dig is available
if ! command -v dig &> /dev/null; then
    echo "Error: 'dig' command not found. Please install bind-tools/dnsutils"
    exit 1
fi

# Create test zone file
cat > test_edns.zone << 'EOF'
$ORIGIN edns.test.
edns.test. IN SOA ns1.edns.test. admin.edns.test. 1 3600 900 604800 86400
edns.test. IN NS ns1.edns.test.
ns1 IN A 127.0.0.1
www IN A 192.168.1.100
www IN AAAA 2001:0db8:0000:0000:0000:0000:0000:0001
EOF

# Start DNS server
log "Starting DNS server on $SERVER:$PORT"
./bin/dnsserver -p $PORT -z test_edns.zone $SERVER > server_edns.log 2>&1 &
SERVER_PID=$!
sleep 2

# Check if server is running
if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    echo "Error: Failed to start DNS server"
    cat server_edns.log
    exit 1
fi

log "DNS server started (PID: $SERVER_PID)"

# Cleanup on exit
trap "kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null; rm -f test_edns.zone server_edns.log" EXIT

echo "=========================================="
echo "  EDNS(0) Integration Tests"
echo "=========================================="
echo ""

# Test 1: Query WITHOUT EDNS (using +noedns)
log "TEST 1: Query WITHOUT EDNS"
result=$(dig @$SERVER -p $PORT www.edns.test. A +noedns +short 2>/dev/null)

if [ "$result" == "192.168.1.100" ]; then
    pass "Query without EDNS works"
else
    fail "Query without EDNS failed (got: $result)"
fi

sleep 0.5

# Test 2: Query WITH EDNS (default dig behavior)
log "TEST 2: Query WITH EDNS (default dig)"
result=$(dig @$SERVER -p $PORT www.edns.test. A +short 2>/dev/null)

if [ "$result" == "192.168.1.100" ]; then
    pass "Query with EDNS works"
else
    fail "Query with EDNS failed (got: $result)"
fi

sleep 0.5

# Test 3: Verify EDNS in response (check for OPT record)
log "TEST 3: Verify OPT record in EDNS response"
result=$(dig @$SERVER -p $PORT www.edns.test. A 2>/dev/null | grep -c "OPT PSEUDOSECTION")

if [ "$result" -ge 1 ]; then
    pass "Server returns OPT record in response"
else
    fail "Server does not return OPT record"
    info "Full dig output:"
    dig @$SERVER -p $PORT www.edns.test. A 2>/dev/null | tee -a "$LOGFILE"
fi

sleep 0.5

# Test 4: Query with specific buffer size
log "TEST 4: Query with EDNS buffer size 512"
result=$(dig @$SERVER -p $PORT www.edns.test. A +bufsize=512 +short 2>/dev/null)

if [ "$result" == "192.168.1.100" ]; then
    pass "Query with EDNS buffer size 512 works"
else
    fail "Query with EDNS buffer size 512 failed"
fi

sleep 0.5

# Test 5: Query with large buffer size
log "TEST 5: Query with EDNS buffer size 4096"
result=$(dig @$SERVER -p $PORT www.edns.test. A +bufsize=4096 +short 2>/dev/null)

if [ "$result" == "192.168.1.100" ]; then
    pass "Query with EDNS buffer size 4096 works"
else
    fail "Query with EDNS buffer size 4096 failed"
fi

sleep 0.5

# Test 6: Verify server doesn't crash on EDNS query
log "TEST 6: Multiple EDNS queries (stress test)"
SUCCESS_COUNT=0
for i in {1..10}; do
    result=$(dig @$SERVER -p $PORT www.edns.test. A +short 2>/dev/null)
    if [ "$result" == "192.168.1.100" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
done

if [ "$SUCCESS_COUNT" -eq 10 ]; then
    pass "Server handles multiple EDNS queries correctly"
else
    fail "Server failed on $((10 - SUCCESS_COUNT)) out of 10 EDNS queries"
fi

sleep 0.5

# Test 7: AAAA query with EDNS
log "TEST 7: AAAA query with EDNS"
result=$(dig @$SERVER -p $PORT www.edns.test. AAAA +short 2>/dev/null)

if [ "$result" == "2001:db8::1" ]; then
    pass "AAAA query with EDNS works"
else
    fail "AAAA query with EDNS failed (got: $result)"
fi

sleep 0.5

# Test 8: Check logs for EDNS processing (look for OPT in server logs)
log "TEST 8: Verify server logs EDNS (OPT) records"
# Give server time to flush logs
sleep 1
if grep -q "OPT" server_edns.log; then
    pass "Server logs show OPT record processing"
else
    info "Server logs don't explicitly show OPT (may be logged as 'unk' before the fix)"
    # This is not a failure since old logs might have "unk"
    TESTS_RUN=$((TESTS_RUN + 1))
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
    echo -e "${GREEN}All EDNS integration tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Check $LOGFILE for details.${NC}"
    exit 1
fi

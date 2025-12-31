#!/bin/bash
# DNS UPDATE Integration Test Suite
# Tests RFC 2136 UPDATE operations

set -e

SERVER="127.0.0.1"
PORT="15353"
ZONE="test.example.com"
LOGFILE="test_update.log"

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

skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    log "SKIP: $1"
}

# Initialize test log
echo "DNS UPDATE Test Suite - $(date)" > "$LOGFILE"
log "Testing server: $SERVER:$PORT"
log "Target zone: $ZONE"
echo ""

# Check if dig is available
if ! command -v dig &> /dev/null; then
    echo "Error: 'dig' command not found. Please install bind-tools/dnsutils"
    exit 1
fi

# Check if nsupdate is available
if ! command -v nsupdate &> /dev/null; then
    echo "Warning: 'nsupdate' command not found. Some tests will be skipped."
    NSUPDATE_AVAILABLE=0
else
    NSUPDATE_AVAILABLE=1
fi

# Create test zone file
create_test_zone() {
    cat > test_update.zone << EOF
\$ORIGIN $ZONE
\$ACL 0.0.0.0/0
$ZONE. IN SOA ns1.$ZONE. admin.$ZONE. 2025123101 3600 1800 604800 86400
$ZONE. IN NS ns1.$ZONE.
ns1.$ZONE. IN A 127.0.0.1
EOF
}

# Start DNS server
start_server() {
    log "Starting DNS server on $SERVER:$PORT"
    create_test_zone
    ./dnsserver -p $PORT test_update.zone $SERVER > server.log 2>&1 &
    local starter_pid=$!
    wait $starter_pid 2>/dev/null  # Wait for parent to exit after fork
    sleep 1
    
    # Find the actual server process (the forked child)
    SERVER_PID=$(ps aux | grep "[d]nsserver -p $PORT" | awk '{print $2}')
    
    if [ -z "$SERVER_PID" ]; then
        echo "Error: Failed to start DNS server"
        cat server.log
        exit 1
    fi
    
    log "DNS server started (PID: $SERVER_PID)"
}

# Stop DNS server
stop_server() {
    if [ -n "$SERVER_PID" ]; then
        log "Stopping DNS server (PID: $SERVER_PID)"
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}

# Test helper: Send raw DNS UPDATE packet
send_update_raw() {
    local update_data="$1"
    # This would need a tool like 'dig' with UPDATE support or custom tool
    # For now, we'll use nsupdate
    echo "$update_data" | nsupdate -v
}

# Test helper: Query DNS record
query_record() {
    local name="$1"
    local type="${2:-A}"
    dig @"$SERVER" -p "$PORT" "$name" "$type" +short +tries=1 +time=2 2>/dev/null
}

# Test helper: Check if record exists
record_exists() {
    local name="$1"
    local type="${2:-A}"
    [ -n "$(query_record "$name" "$type")" ]
}

echo "=========================================="
echo "  DNS UPDATE RFC 2136 Test Suite"
echo "=========================================="
echo ""

# ============================================================
# TEST 1: Basic UPDATE - Add A Record
# ============================================================
test_add_a_record() {
    log "TEST 1: Add A record via UPDATE"
    local hostname="test1.$ZONE"
    local ip="10.0.0.1"
    
    if [ $NSUPDATE_AVAILABLE -eq 0 ]; then
        skip "Add A record (nsupdate not available)"
        return
    fi
    
    # Send UPDATE
    cat <<EOF | nsupdate -v 2>&1 | tee -a "$LOGFILE"
server $SERVER $PORT
zone $ZONE
update add $hostname 300 A $ip
send
EOF
    
    sleep 1
    
    # Query back
    result=$(query_record "$hostname" A)
    
    if [ "$result" == "$ip" ]; then
        pass "Add A record: $hostname -> $ip"
    else
        fail "Add A record: Expected $ip, got '$result'"
    fi
}

# ============================================================
# TEST 2: UPDATE with Prerequisite - Zone Must Exist
# ============================================================
test_prereq_zone_exists() {
    log "TEST 2: UPDATE with prerequisite - zone exists"
    local hostname="test2.$ZONE"
    local ip="10.0.0.2"
    
    if [ $NSUPDATE_AVAILABLE -eq 0 ]; then
        skip "Prerequisite zone exists (nsupdate not available)"
        return
    fi
    
    # Update with zone prerequisite
    cat <<EOF | nsupdate -v 2>&1 | tee -a "$LOGFILE"
server $SERVER $PORT
zone $ZONE
prereq yxdomain $ZONE
update add $hostname 300 A $ip
send
EOF
    
    sleep 1
    
    result=$(query_record "$hostname" A)
    
    if [ "$result" == "$ip" ]; then
        pass "Prerequisite zone exists: UPDATE successful"
    else
        fail "Prerequisite zone exists: Expected $ip, got '$result'"
    fi
}

# ============================================================
# TEST 3: UPDATE with Prerequisite - Name Must Not Exist
# ============================================================
test_prereq_name_not_exists() {
    log "TEST 3: UPDATE with prerequisite - name not in use"
    local hostname="test3.$ZONE"
    local ip="10.0.0.3"
    
    if [ $NSUPDATE_AVAILABLE -eq 0 ]; then
        skip "Prerequisite name not exists (nsupdate not available)"
        return
    fi
    
    # Update with name not exists prerequisite
    cat <<EOF | nsupdate -v 2>&1 | tee -a "$LOGFILE"
server $SERVER $PORT
zone $ZONE
prereq nxdomain $hostname
update add $hostname 300 A $ip
send
EOF
    
    sleep 1
    
    result=$(query_record "$hostname" A)
    
    if [ "$result" == "$ip" ]; then
        pass "Prerequisite name not exists: UPDATE successful"
    else
        fail "Prerequisite name not exists: Expected $ip, got '$result'"
    fi
}

# ============================================================
# TEST 4: UPDATE - Delete Specific Record
# ============================================================
test_delete_record() {
    log "TEST 4: Delete specific A record"
    local hostname="test4.$ZONE"
    local ip="10.0.0.4"
    
    if [ $NSUPDATE_AVAILABLE -eq 0 ]; then
        skip "Delete record (nsupdate not available)"
        return
    fi
    
    # First add the record
    cat <<EOF | nsupdate 2>&1 | tee -a "$LOGFILE"
server $SERVER $PORT
zone $ZONE
update add $hostname 300 A $ip
send
EOF
    
    sleep 1
    
    # Verify it was added
    if ! record_exists "$hostname" A; then
        fail "Delete record: Setup failed - record not added"
        return
    fi
    
    # Now delete it
    cat <<EOF | nsupdate 2>&1 | tee -a "$LOGFILE"
server $SERVER $PORT
zone $ZONE
update delete $hostname A $ip
send
EOF
    
    sleep 1
    
    # Verify deletion
    if ! record_exists "$hostname" A; then
        pass "Delete specific record: Record successfully deleted"
    else
        fail "Delete specific record: Record still exists"
    fi
}

# ============================================================
# TEST 5: UPDATE - Delete All Records of Type
# ============================================================
test_delete_rrset() {
    log "TEST 5: Delete entire RRset (all A records)"
    local hostname="test5.$ZONE"
    
    if [ $NSUPDATE_AVAILABLE -eq 0 ]; then
        skip "Delete RRset (nsupdate not available)"
        return
    fi
    
    # Add multiple A records
    cat <<EOF | nsupdate 2>&1 | tee -a "$LOGFILE"
server $SERVER $PORT
zone $ZONE
update add $hostname 300 A 10.0.0.5
update add $hostname 300 A 10.0.0.6
send
EOF
    
    sleep 1
    
    # Verify records exist
    count=$(query_record "$hostname" A | wc -l)
    if [ "$count" -lt 2 ]; then
        fail "Delete RRset: Setup failed - multiple records not added"
        return
    fi
    
    # Delete all A records
    cat <<EOF | nsupdate 2>&1 | tee -a "$LOGFILE"
server $SERVER $PORT
zone $ZONE
update delete $hostname A
send
EOF
    
    sleep 1
    
    # Verify deletion
    if ! record_exists "$hostname" A; then
        pass "Delete RRset: All A records deleted"
    else
        fail "Delete RRset: Some records still exist"
    fi
}

# ============================================================
# TEST 6: UPDATE - Add DHCID Record
# ============================================================
test_add_dhcid_record() {
    log "TEST 6: Add A record with DHCID lease binding"
    local hostname="test6.$ZONE"
    local ip="10.0.0.7"
    local dhcid="AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="
    
    if [ $NSUPDATE_AVAILABLE -eq 0 ]; then
        skip "Add DHCID record (nsupdate not available)"
        return
    fi
    
    # Add A record with DHCID
    cat <<EOF | nsupdate -v 2>&1 | tee -a "$LOGFILE"
server $SERVER $PORT
zone $ZONE
update add $hostname 3600 A $ip
update add $hostname 3600 DHCID $dhcid
send
EOF
    
    sleep 1
    
    # Query A record
    result_a=$(query_record "$hostname" A)
    result_dhcid=$(query_record "$hostname" DHCID)
    
    if [ "$result_a" == "$ip" ] && [ -n "$result_dhcid" ]; then
        pass "Add DHCID record: A and DHCID records added"
    elif [ "$result_a" == "$ip" ]; then
        fail "Add DHCID record: A record added but DHCID missing"
    else
        fail "Add DHCID record: Failed to add records"
    fi
}

# ============================================================
# TEST 7: UPDATE - Failed Prerequisite
# ============================================================
test_failed_prerequisite() {
    log "TEST 7: UPDATE with failing prerequisite"
    local hostname="nonexistent.test.$ZONE"
    local ip="10.0.0.8"
    
    if [ $NSUPDATE_AVAILABLE -eq 0 ]; then
        skip "Failed prerequisite (nsupdate not available)"
        return
    fi
    
    # Try to update record that must exist (but doesn't)
    output=$(cat <<EOF | nsupdate -v 2>&1
server $SERVER $PORT
zone $ZONE
prereq yxrrset $hostname A
update add $hostname 300 A $ip
send
EOF
)
    
    # Check if update was rejected
    if echo "$output" | grep -q -i "NXRRSET\|prerequisite"; then
        pass "Failed prerequisite: UPDATE correctly rejected"
    else
        # Check if record was not added
        if ! record_exists "$hostname" A; then
            pass "Failed prerequisite: UPDATE rejected (no record added)"
        else
            fail "Failed prerequisite: UPDATE should have been rejected"
        fi
    fi
}

# ============================================================
# TEST 8: UPDATE - Replace Record (Delete + Add)
# ============================================================
test_replace_record() {
    log "TEST 8: Replace A record"
    local hostname="test8.$ZONE"
    local ip_old="10.0.0.9"
    local ip_new="10.0.0.10"
    
    if [ $NSUPDATE_AVAILABLE -eq 0 ]; then
        skip "Replace record (nsupdate not available)"
        return
    fi
    
    # Add initial record
    cat <<EOF | nsupdate 2>&1 | tee -a "$LOGFILE"
server $SERVER $PORT
zone $ZONE
update add $hostname 300 A $ip_old
send
EOF
    
    sleep 1
    
    # Replace with new IP
    cat <<EOF | nsupdate 2>&1 | tee -a "$LOGFILE"
server $SERVER $PORT
zone $ZONE
update delete $hostname A
update add $hostname 300 A $ip_new
send
EOF
    
    sleep 1
    
    result=$(query_record "$hostname" A)
    
    if [ "$result" == "$ip_new" ]; then
        pass "Replace record: IP updated from $ip_old to $ip_new"
    else
        fail "Replace record: Expected $ip_new, got '$result'"
    fi
}

# ============================================================
# Run All Tests
# ============================================================

# Trap to ensure cleanup on exit
trap stop_server EXIT INT TERM

# Start the server
start_server

echo "Starting tests..."
echo ""

test_add_a_record
test_prereq_zone_exists
test_prereq_name_not_exists
test_delete_record
test_delete_rrset
test_add_dhcid_record
test_failed_prerequisite
test_replace_record

# Stop the server
stop_server

# ============================================================
# Test Summary
# ============================================================
echo ""
echo "=========================================="
echo "  Test Summary"
echo "=========================================="
echo "Total tests run:    $TESTS_RUN"
echo -e "Tests passed:       ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed:       ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Check $LOGFILE for details.${NC}"
    exit 1
fi

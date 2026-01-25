#!/bin/bash
# DNS DYNAMIC Record Integration Test
# Tests $DYNAMIC directive for ACME challenges

set -e

SERVER="127.0.0.1"
PORT="15357"
ZONE_FILE="/tmp/test_dynamic_integration.zone"
CHALLENGE_FILE="/tmp/dynamic_test_challenge.txt"
CHALLENGE_FILE2="/tmp/dynamic_test_challenge2.txt"

echo "=========================================="
echo "  DNS DYNAMIC Record Integration Test"
echo "=========================================="
echo ""

# Create test zone file
cat > $ZONE_FILE << 'EOF'
$ORIGIN example.com.
@ 3600 IN SOA ns1.example.com. admin.example.com. 2024012501 3600 1800 604800 86400
@ 3600 IN NS ns1.example.com.
ns1 3600 IN A 192.0.2.1
test 60 IN TXT "static record"

; Dynamic records for ACME challenges
$DYNAMIC _acme-challenge /tmp/dynamic_test_challenge.txt
$DYNAMIC _acme-challenge.www /tmp/dynamic_test_challenge2.txt
EOF

# Start server
echo "Starting DNS server..."
./bin/dnsserver -p $PORT -z $ZONE_FILE $SERVER > /tmp/dynamic_test.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    echo "ERROR: Failed to start DNS server"
    cat /tmp/dynamic_test.log
    exit 1
fi

echo "Server started (PID: $SERVER_PID)"
echo ""

# Cleanup on exit
trap "kill $SERVER_PID 2>/dev/null || true; wait $SERVER_PID 2>/dev/null || true; rm -f $ZONE_FILE $CHALLENGE_FILE $CHALLENGE_FILE2" EXIT

# Run tests
PASSED=0
FAILED=0

test_query() {
    local name=$1
    local expected=$2
    local description=$3
    
    result=$(dig @$SERVER -p $PORT "$name" TXT +short +tries=1 +time=2 2>/dev/null | sort)
    
    if [ "$result" = "$expected" ]; then
        echo "[PASS] $description"
        PASSED=$((PASSED + 1))
    else
        echo "[FAIL] $description"
        echo "  Expected: $expected"
        echo "  Got:      $result"
        FAILED=$((FAILED + 1))
    fi
}

echo "Running tests..."
echo ""

# Test 1: No file exists - should return no records
test_query "_acme-challenge.example.com" "" "No file exists - empty response"

# Test 2: Create challenge file
echo "challenge-token-123" > $CHALLENGE_FILE
expected="\"challenge-token-123\""
test_query "_acme-challenge.example.com" "$expected" "Single token from file"

# Test 3: Update challenge file
echo "challenge-token-456" > $CHALLENGE_FILE
expected="\"challenge-token-456\""
test_query "_acme-challenge.example.com" "$expected" "Updated token (real-time)"

# Test 4: Multiple tokens with deduplication
cat > $CHALLENGE_FILE << 'MULTI'
token-c
token-a
token-b
token-a
MULTI
expected=$(printf '"token-a"\n"token-b"\n"token-c"')
test_query "_acme-challenge.example.com" "$expected" "Multiple tokens (sorted, deduplicated)"

# Test 5: Separate dynamic record
echo "wildcard-token" > $CHALLENGE_FILE2
expected="\"wildcard-token\""
test_query "_acme-challenge.www.example.com" "$expected" "Separate dynamic record (www)"

# Test 6: First record still works independently
result=$(dig @$SERVER -p $PORT "_acme-challenge.example.com" TXT +short 2>/dev/null | wc -l)
if [ "$result" -eq 3 ]; then
    echo "[PASS] First record unchanged by second"
    PASSED=$((PASSED + 1))
else
    echo "[FAIL] First record affected by second (expected 3, got $result)"
    FAILED=$((FAILED + 1))
fi

# Test 7: Remove file - should return no records
rm -f $CHALLENGE_FILE
test_query "_acme-challenge.example.com" "" "File removed - empty response"

# Test 8: Static TXT records still work
expected="\"\\\"static record\\\"\""
test_query "test.example.com" "$expected" "Static TXT record unaffected"

# Test 9: Empty file
touch $CHALLENGE_FILE
test_query "_acme-challenge.example.com" "" "Empty file - empty response"

# Test 10: Whitespace handling
cat > $CHALLENGE_FILE << 'WHITESPACE'
  token-with-leading-space
token-with-trailing-space  

  token-with-both  
WHITESPACE
expected=$(printf '"token-with-both"\n"token-with-leading-space"\n"token-with-trailing-space"')
test_query "_acme-challenge.example.com" "$expected" "Whitespace trimmed correctly"

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

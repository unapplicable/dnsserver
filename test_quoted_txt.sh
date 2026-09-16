#!/bin/bash
# Quoted TXT record integration test (DKIM / DMARC style semicolons)
set -e

SERVER="127.0.0.1"
PORT="15357"
ZONE_FILE="test_quoted_txt.zone"

echo "=========================================="
echo "  DNS Quoted TXT Integration Test"
echo "=========================================="
echo ""

./bin/dnsserver -p $PORT -z $ZONE_FILE $SERVER > /tmp/quoted_txt_test.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    echo "ERROR: Failed to start DNS server"
    cat /tmp/quoted_txt_test.log
    exit 1
fi
echo "Server started (PID: $SERVER_PID)"
echo ""
trap "kill $SERVER_PID 2>/dev/null || true; wait $SERVER_PID 2>/dev/null || true" EXIT

PASSED=0
FAILED=0

check_txt() {
    local name=$1
    local expected=$2
    local desc=$3
    local got
    got=$(dig @$SERVER -p $PORT TXT "$name" +short +tries=1 +time=2 2>/dev/null | tr -d '\n')
    if [ "$got" = "\"$expected\"" ]; then
        echo "[PASS] $desc"
        PASSED=$((PASSED + 1))
    else
        echo "[FAIL] $desc (expected \"$expected\", got: $got)"
        FAILED=$((FAILED + 1))
    fi
}

check_txt "dkim.example.com."     "v=DKIM1; k=rsa; p=abcdefghij"        "DKIM TXT value with semicolons survives"
check_txt "dmarc.example.com."    "v=DMARC1; p=none; rua=mailto:x@example.com" "DMARC TXT value with semicolons survives"
check_txt "example.com."          "v=spf1 a mx ~all"                    "unquoted multi-token SPF TXT still works"

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
#!/bin/bash
# Quoted TXT record integration test (DKIM / DMARC style semicolons)
set -e

SERVER="127.0.0.1"
PORT="15357"
ZONE_FILE="test_quoted_txt.zone"

LONG_P=$(printf 'A%.0s' $(seq 1 392))

# Build the zone file so the long record's p= is guaranteed to match $LONG_P
cat > "$ZONE_FILE" <<EOF
\$ORIGIN example.com
example.com.			IN	A	192.0.2.1
example.com.			IN	TXT	v=spf1 a mx ~all
dkim.example.com.			IN	TXT	"v=DKIM1; k=rsa; p=abcdefghij"
dmarc.example.com.			IN	TXT	"v=DMARC1; p=none; rua=mailto:x@example.com"
longd.example.com.			IN	TXT	"v=DKIM1; k=rsa; p=$LONG_P"
EOF

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
    got=$(dig @$SERVER -p $PORT TXT "$name" +short +tries=1 +time=2 2>/dev/null | tr -d '"\n ')
    # normalize both sides: strip quotes and whitespace (long TXT values are
    # returned as multiple quoted character-strings by dig)
    if [ "$got" = "$(printf '%s' "$expected" | tr -d '"\n ')" ]; then
        echo "[PASS] $desc"
        PASSED=$((PASSED + 1))
    else
        echo "[FAIL] $desc (expected \"$expected\", got: $got)"
        FAILED=$((FAILED + 1))
    fi
}

LONG_P=$(printf 'A%.0s' $(seq 1 392))
check_txt "dkim.example.com."     "v=DKIM1; k=rsa; p=abcdefghij"        "DKIM TXT value with semicolons survives"
check_txt "dmarc.example.com."    "v=DMARC1; p=none; rua=mailto:x@example.com" "DMARC TXT value with semicolons survives"
check_txt "example.com."          "v=spf1 a mx ~all"                    "unquoted multi-token SPF TXT still works"
check_txt "longd.example.com."    "v=DKIM1; k=rsa; p=$LONG_P"           "long (>255 byte) TXT value round-trips over the wire"

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
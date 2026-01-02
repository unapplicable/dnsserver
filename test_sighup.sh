#!/bin/bash

# Test SIGHUP zone reload functionality including auto-save

set -e

TEST_ZONE="test_sighup.zone"
TEST_BACKUP="test_sighup.zone.bak"
TEST_KEY="test_sighup_key.conf"

# Cleanup function
cleanup() {
    if [ ! -z "$SERVER_PID" ]; then
        echo "Killing server (PID: $SERVER_PID)..."
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    rm -f "$TEST_ZONE" "$TEST_BACKUP" "$TEST_KEY" test_sighup.log
}

trap cleanup EXIT

# Create TSIG key for dynamic updates  
cat > "$TEST_KEY" <<EOF
key "update-key" {
    algorithm hmac-sha256;
    secret "dGVzdGtleTE2Yml0c3NlY3JldDEyMzQ1Njc4OTA=";
};
EOF

# Create initial zone file with auto-save enabled
cat > "$TEST_ZONE" <<EOF
\$ORIGIN test.sighup.
\$TTL 3600
\$AUTOSAVE yes
\$ACL 0.0.0.0/0
\$TSIG update-key hmac-sha256 dGVzdGtleTE2Yml0c3NlY3JldDEyMzQ1Njc4OTA=
@ IN SOA ns1.test.sighup. admin.test.sighup. 2024010101 3600 1800 604800 86400
@ IN NS ns1.test.sighup.
ns1 IN A 192.168.1.1
host1 IN A 10.0.0.1
EOF

echo "Starting DNS server on port 15353..."
./bin/dnsserver -p 15353 -z "$TEST_ZONE" 127.0.0.1 > test_sighup.log 2>&1 &
SERVER_PID=$!

echo "Server started with PID: $SERVER_PID"
sleep 2

# Test 1: Query initial record
echo "Test 1: Query initial record (host1.test.sighup)"
RESULT=$(dig @127.0.0.1 -p 15353 host1.test.sighup A +short 2>/dev/null || echo "FAILED")
if [ "$RESULT" != "10.0.0.1" ]; then
    echo "FAILED: Expected 10.0.0.1, got: $RESULT"
    exit 1
fi
echo "PASSED: Got expected 10.0.0.1"

# Test 2: Send dynamic update to add a record (without TSIG verification for now)
echo ""
echo "Test 2: Sending dynamic DNS update to add host-dyn.test.sighup..."
cat << 'EOF' | nsupdate -k "$TEST_KEY" 2>&1 | tee update_output.txt
server 127.0.0.1 15353
zone test.sighup.
update add host-dyn.test.sighup. 300 A 192.168.100.100
send
quit
EOF

sleep 1

# Verify the dynamic update worked
echo "Verifying dynamic update..."
RESULT=$(dig @127.0.0.1 -p 15353 host-dyn.test.sighup A +short 2>/dev/null || echo "FAILED")
if [ "$RESULT" != "192.168.100.100" ]; then
    echo "FAILED: Expected 192.168.100.100, got: $RESULT"
    cat test_sighup.log
    exit 1
fi
echo "PASSED: Dynamic record exists in memory"

# Test 3: Send SIGHUP to trigger save and reload
echo ""
echo "Test 3: Sending SIGHUP to save modified zone and reload..."
kill -HUP $SERVER_PID
sleep 3

# Verify the record still exists after reload
echo "Verifying record persisted after SIGHUP..."
RESULT=$(dig @127.0.0.1 -p 15353 host-dyn.test.sighup A +short 2>/dev/null || echo "FAILED")
if [ "$RESULT" != "192.168.100.100" ]; then
    echo "FAILED: Expected 192.168.100.100 after reload, got: $RESULT"
    cat test_sighup.log
    exit 1
fi
echo "PASSED: Dynamic record persisted to disk and reloaded"

# Test 4: Verify zone file was actually saved
echo ""
echo "Test 4: Verifying zone file contains the dynamic record..."
if ! grep -q "host-dyn" "$TEST_ZONE"; then
    echo "FAILED: Zone file does not contain host-dyn record"
    cat "$TEST_ZONE"
    exit 1
fi
echo "PASSED: Zone file contains the dynamic record"

# Test 5: Modify zone file manually
echo ""
echo "Test 5: Manually modifying zone file..."
cat > "$TEST_ZONE" <<EOF
\$ORIGIN test.sighup.
\$TTL 3600
\$AUTOSAVE yes
\$ACL 0.0.0.0/0
\$TSIG update-key hmac-sha256 dGVzdGtleTE2Yml0c3NlY3JldDEyMzQ1Njc4OTA=
@ IN SOA ns1.test.sighup. admin.test.sighup. 2024010102 3600 1800 604800 86400
@ IN NS ns1.test.sighup.
ns1 IN A 192.168.1.1
host1 IN A 10.0.0.2
host2 IN A 10.0.0.3
EOF

# Send SIGHUP to reload
echo "Sending SIGHUP to reload..."
kill -HUP $SERVER_PID
sleep 2

# Test 6: Query modified record
echo ""
echo "Test 6: Query modified record (host1.test.sighup should now be 10.0.0.2)"
RESULT=$(dig @127.0.0.1 -p 15353 host1.test.sighup A +short 2>/dev/null || echo "FAILED")
if [ "$RESULT" != "10.0.0.2" ]; then
    echo "FAILED: Expected 10.0.0.2, got: $RESULT"
    exit 1
fi
echo "PASSED: Got expected 10.0.0.2"

# Test 7: Query new record
echo ""
echo "Test 7: Query new record (host2.test.sighup)"
RESULT=$(dig @127.0.0.1 -p 15353 host2.test.sighup A +short 2>/dev/null || echo "FAILED")
if [ "$RESULT" != "10.0.0.3" ]; then
    echo "FAILED: Expected 10.0.0.3, got: $RESULT"
    exit 1
fi
echo "PASSED: Got expected 10.0.0.3"

# Test 8: Verify old dynamic record was removed
echo ""
echo "Test 8: Verify old dynamic record was removed after manual edit"
RESULT=$(dig @127.0.0.1 -p 15353 host-dyn.test.sighup A +short 2>/dev/null || echo "")
if [ ! -z "$RESULT" ]; then
    echo "FAILED: Old dynamic record should be gone, got: $RESULT"
    exit 1
fi
echo "PASSED: Old dynamic record correctly removed"

echo ""
echo "All SIGHUP tests passed!"

exit 0

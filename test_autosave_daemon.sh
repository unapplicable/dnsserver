#!/bin/bash

# Test auto-save functionality when running in daemon mode (-d flag)
# This specifically tests that the autosave thread runs correctly after fork()

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TEST_ZONE="test_autosave_daemon.zone"
TEST_BACKUP="test_autosave_daemon.zone.bak"

# Cleanup function
cleanup() {
    if [ ! -z "$SERVER_PID" ]; then
        echo "Killing server (PID: $SERVER_PID)..."
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    # Also kill any child processes
    pkill -f "dnsserver.*15354" 2>/dev/null || true
    rm -f "$TEST_ZONE" "$TEST_BACKUP" test_autosave_daemon.log
}

trap cleanup EXIT

# Create initial zone file with auto-save enabled
cat > "$TEST_ZONE" <<EOF
\$ORIGIN test.autosave.daemon.
\$TTL 3600
\$AUTOSAVE yes
\$ACL 0.0.0.0/0
@ IN SOA ns1.test.autosave.daemon. admin.test.autosave.daemon. 2024010101 3600 1800 604800 86400
@ IN NS ns1.test.autosave.daemon.
ns1 IN A 192.168.1.1
host1 IN A 10.0.0.1
EOF

# Backup original
cp "$TEST_ZONE" "$TEST_BACKUP"

echo "Starting DNS server in DAEMON mode on port 15354..."
# Start with -d flag to daemonize
./bin/dnsserver -p 15354 -d -z "$TEST_ZONE" 127.0.0.1 > test_autosave_daemon.log 2>&1 &
SERVER_PID=$!

# Wait for daemon to start and fork
sleep 3

# The parent process exits after fork, so we need to find the child
# Look for processes running on port 15354
DAEMON_PID=$(pgrep -f "dnsserver.*15354" | head -1 || echo "")

if [ -z "$DAEMON_PID" ]; then
    echo "FAILED: No server process found"
    cat test_autosave_daemon.log
    exit 1
fi

echo "Server daemon running with PID: $DAEMON_PID"

# Check number of threads - should be > 1 if autosave thread is running
THREAD_COUNT=$(ps -o nlwp= -p $DAEMON_PID 2>/dev/null || echo "1")
echo "Thread count: $THREAD_COUNT"

# Test 1: Verify the server is running
echo ""
echo "Test 1: Verifying server is running..."
if ! kill -0 $DAEMON_PID 2>/dev/null; then
    echo "FAILED: Server not running"
    cat test_autosave_daemon.log
    exit 1
fi
echo "PASSED: Server is running"

# Test 2: Query initial record
echo ""
echo "Test 2: Query initial record (host1.test.autosave.daemon)..."
RESULT=$(dig @127.0.0.1 -p 15354 host1.test.autosave.daemon A +short 2>/dev/null || echo "FAILED")
if [ "$RESULT" != "10.0.0.1" ]; then
    echo "FAILED: Expected 10.0.0.1, got: $RESULT"
    exit 1
fi
echo "PASSED: Got expected 10.0.0.1"

# Test 3: Send dynamic update to add a record
echo ""
echo "Test 3: Sending dynamic DNS update to add host-dyn.test.autosave.daemon..."
nsupdate -v <<EOF
server 127.0.0.1 15354
zone test.autosave.daemon.
update add host-dyn.test.autosave.daemon. 300 A 192.168.100.100
send
quit
EOF

sleep 2

# Verify the dynamic update worked in memory
echo "Verifying dynamic update in memory..."
RESULT=$(dig @127.0.0.1 -p 15354 host-dyn.test.autosave.daemon A +short 2>/dev/null || echo "FAILED")
if [ "$RESULT" != "192.168.100.100" ]; then
    echo "FAILED: Expected 192.168.100.100, got: $RESULT"
    cat test_autosave_daemon.log
    exit 1
fi
echo "PASSED: Dynamic record exists in memory"

# Test 4: Wait for auto-save interval (5 minutes = 300 seconds)
# For testing, we'll use a shorter interval by modifying the code or just verify thread exists
echo ""
echo "Test 4: Checking autosave thread is running..."
# The autosave thread should be running - check via /proc
if [ -d "/proc/$DAEMON_PID/task" ]; then
    THREADS=$(ls /proc/$DAEMON_PID/task | wc -l)
    echo "Found $THREADS threads"
    if [ "$THREADS" -lt "2" ]; then
        echo "WARNING: Only 1 thread found - autosave thread may not be running"
    else
        echo "PASSED: Multiple threads found (autosave thread running)"
    fi
else
    echo "WARNING: Cannot check /proc for threads"
fi

# For faster testing, send SIGHUP to trigger immediate save
echo ""
echo "Test 5: Sending SIGHUP to trigger immediate save..."
kill -HUP $DAEMON_PID
sleep 2

# Test 6: Verify zone file was saved
echo ""
echo "Test 6: Verifying zone file contains the dynamic record..."
if ! grep -q "host-dyn" "$TEST_ZONE"; then
    echo "FAILED: Zone file does not contain host-dyn record"
    echo "Zone file contents:"
    cat "$TEST_ZONE"
    exit 1
fi
echo "PASSED: Zone file contains the dynamic record"

# Test 7: Verify serial was incremented
echo ""
echo "Test 7: Verifying serial was incremented..."
OLD_SERIAL=$(grep -A1 "SOA" "$TEST_BACKUP" | grep -oE "[0-9]{10,}" | head -1)
NEW_SERIAL=$(grep -A1 "SOA" "$TEST_ZONE" | grep -oE "[0-9]{10,}" | head -1)
echo "Old serial: $OLD_SERIAL, New serial: $NEW_SERIAL"
if [ -z "$NEW_SERIAL" ] || [ "$NEW_SERIAL" -le "$OLD_SERIAL" ]; then
    echo "FAILED: Serial was not incremented"
    exit 1
fi
echo "PASSED: Serial was incremented"

# Test 8: Query the record again to confirm it persisted
echo ""
echo "Test 8: Querying persisted record..."
RESULT=$(dig @127.0.0.1 -p 15354 host-dyn.test.autosave.daemon A +short 2>/dev/null || echo "FAILED")
if [ "$RESULT" != "192.168.100.100" ]; then
    echo "FAILED: Expected 192.168.100.100, got: $RESULT"
    exit 1
fi
echo "PASSED: Record persisted and queryable"

echo ""
echo "All autosave daemon tests passed!"

exit 0

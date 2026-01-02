#!/bin/bash
# Mutation Testing Script

TIMEOUT=60
TEST_CMD="timeout ${TIMEOUT} make test"
INTEGRATION_TEST_CMD="timeout ${TIMEOUT} make test-integration"

echo "=== MUTATION TESTING REPORT ===" > MUTATION_TESTING_REPORT.md
echo "" >> MUTATION_TESTING_REPORT.md
echo "Testing critical functionality mutations to verify test coverage" >> MUTATION_TESTING_REPORT.md
echo "" >> MUTATION_TESTING_REPORT.md

run_mutation_test() {
    local mutation_name="$1"
    local file="$2"
    local old_code="$3"
    local new_code="$4"
    local test_type="${5:-unit}"
    
    echo "Testing mutation: $mutation_name"
    echo "## Mutation: $mutation_name" >> MUTATION_TESTING_REPORT.md
    echo "File: \`$file\`" >> MUTATION_TESTING_REPORT.md
    echo "" >> MUTATION_TESTING_REPORT.md
    
    # Apply mutation
    if grep -q "$old_code" "$file"; then
        sed -i.bak "s/$old_code/$new_code/" "$file"
        
        # Run tests
        if [ "$test_type" = "integration" ]; then
            if eval $INTEGRATION_TEST_CMD > /dev/null 2>&1; then
                echo "❌ SURVIVED - Tests passed with mutation!" >> MUTATION_TESTING_REPORT.md
                echo "  → Need to add tests for this functionality" >> MUTATION_TESTING_REPORT.md
                result="SURVIVED"
            else
                echo "✅ KILLED - Tests caught the mutation" >> MUTATION_TESTING_REPORT.md
                result="KILLED"
            fi
        else
            if eval $TEST_CMD > /dev/null 2>&1; then
                echo "❌ SURVIVED - Tests passed with mutation!" >> MUTATION_TESTING_REPORT.md
                echo "  → Need to add tests for this functionality" >> MUTATION_TESTING_REPORT.md
                result="SURVIVED"
            else
                echo "✅ KILLED - Tests caught the mutation" >> MUTATION_TESTING_REPORT.md
                result="KILLED"
            fi
        fi
        
        # Revert mutation
        mv "$file.bak" "$file"
        echo "" >> MUTATION_TESTING_REPORT.md
        echo "$result"
    else
        echo "⚠️  SKIPPED - Pattern not found" >> MUTATION_TESTING_REPORT.md
        echo "" >> MUTATION_TESTING_REPORT.md
        echo "SKIPPED"
    fi
}

# Mutation 1: TSIG MAC validation bypass
run_mutation_test "TSIG MAC Validation Bypass" "tsig.cpp" \
    "return computedMac == receivedMac;" \
    "return true; \/\/ MUTATION"

# Mutation 2: TSIG algorithm check bypass
run_mutation_test "TSIG Algorithm Check Bypass" "tsig.cpp" \
    'throw std::runtime_error("Unsupported TSIG algorithm");' \
    'return true; \/\/ MUTATION'

# Mutation 3: Zone authority check bypass
run_mutation_test "Zone Authority Check Bypass" "zone_authority.cpp" \
    "if (!zone) {" \
    "if (false) { \/\/ MUTATION"

# Mutation 4: ACL check bypass
run_mutation_test "ACL Check Bypass" "update_processor.cpp" \
    "if (!acl.isAllowed(clientIp)) {" \
    "if (false) { \/\/ MUTATION"

# Mutation 5: TSIG time fudge check bypass
run_mutation_test "TSIG Time Fudge Bypass" "tsig.cpp" \
    "if (timeDiff > fudge) {" \
    "if (false) { \/\/ MUTATION"

# Mutation 6: Zone modified flag not set
run_mutation_test "Zone Modified Flag Not Set" "zone.cpp" \
    "modified = true;" \
    "modified = false; \/\/ MUTATION"

# Mutation 7: Serial increment broken
run_mutation_test "Serial Increment Broken" "zone.cpp" \
    "currentSerial++;" \
    "currentSerial = currentSerial; \/\/ MUTATION"

# Mutation 8: Wildcard single-level match broken
run_mutation_test "Wildcard Single Level Match Broken" "query_processor.cpp" \
    'if (qname.substr(0, 2) == "\\*\\." && qname.size() > 2) {' \
    'if (false) { \/\/ MUTATION'

# Mutation 9: Wildcard multi-level match broken
run_mutation_test "Wildcard Multi Level Match Broken" "query_processor.cpp" \
    'if (qname.substr(0, 3) == "\\*\\*\\." && qname.size() > 3) {' \
    'if (false) { \/\/ MUTATION'

# Mutation 10: RR type check bypass
run_mutation_test "RR Type Check Bypass" "update_processor.cpp" \
    "if (type == 0) {" \
    "if (false) { \/\/ MUTATION"

# Mutation 11: TTL validation bypass
run_mutation_test "TTL Validation Bypass" "zone.cpp" \
    "if (ttl < 0) {" \
    "if (false) { \/\/ MUTATION"

# Mutation 12: HMAC key empty check bypass
run_mutation_test "HMAC Key Empty Check" "tsig.cpp" \
    "if (keyData.empty()) {" \
    "if (false) { \/\/ MUTATION"

# Mutation 13: Auto-save flag check bypass
run_mutation_test "Auto-Save Flag Check" "zone_authority.cpp" \
    "if (zone->shouldAutoSave()) {" \
    "if (false) { \/\/ MUTATION"

# Mutation 14: Zone file path empty check
run_mutation_test "Zone File Path Empty Check" "zone.cpp" \
    "if (filePath.empty()) {" \
    "if (false) { \/\/ MUTATION"

# Mutation 15: DNS message ID preserved
run_mutation_test "DNS Message ID Not Preserved" "query_processor.cpp" \
    "response.id = query.id;" \
    "response.id = 0; \/\/ MUTATION"

echo "=== Mutation Testing Complete ===" >> MUTATION_TESTING_REPORT.md
echo "" >> MUTATION_TESTING_REPORT.md
echo "Review survived mutations and add tests accordingly." >> MUTATION_TESTING_REPORT.md

cat MUTATION_TESTING_REPORT.md

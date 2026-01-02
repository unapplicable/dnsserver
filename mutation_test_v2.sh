#!/bin/bash

TIMEOUT=60
TEST_CMD="timeout ${TIMEOUT} make test"

echo "=== DETAILED MUTATION TESTING REPORT ===" > MUTATION_TESTING_REPORT.md
echo "Date: $(date)" >> MUTATION_TESTING_REPORT.md
echo "" >> MUTATION_TESTING_REPORT.md

run_mutation() {
    local name="$1"
    local file="$2"
    local line="$3"
    local old="$4"
    local new="$5"
    
    echo "Testing: $name in $file"
    echo "## $name" >> MUTATION_TESTING_REPORT.md
    echo "**File:** \`$file\` (line ~$line)" >> MUTATION_TESTING_REPORT.md
    echo "" >> MUTATION_TESTING_REPORT.md
    
    # Create backup
    cp "$file" "$file.mutbak"
    
    # Apply mutation
    sed -i "${line}s|${old}|${new}|" "$file"
    
    # Run tests
    if $TEST_CMD > /tmp/test_output.txt 2>&1; then
        echo "❌ **SURVIVED** - Tests passed with this bug!" >> MUTATION_TESTING_REPORT.md
        echo "" >> MUTATION_TESTING_REPORT.md
        echo "**Original:** \`$old\`" >> MUTATION_TESTING_REPORT.md
        echo "**Mutated:** \`$new\`" >> MUTATION_TESTING_REPORT.md
        echo "" >> MUTATION_TESTING_REPORT.md
        echo "**Action:** Need additional test coverage for this functionality" >> MUTATION_TESTING_REPORT.md
        result="SURVIVED"
    else
        echo "✅ **KILLED** - Tests caught this mutation" >> MUTATION_TESTING_REPORT.md
        result="KILLED"
    fi
    
    # Restore
    mv "$file.mutbak" "$file"
    echo "" >> MUTATION_TESTING_REPORT.md
    echo "$name: $result"
}

# Mutation 1: TSIG MAC comparison
run_mutation "TSIG MAC Verification Bypass" "tsig.cpp" 303 \
    'if (expected_mac != tsig->mac) {' \
    'if (false) {'

# Mutation 2: TSIG time check
run_mutation "TSIG Time Check Bypass" "tsig.cpp" 291 \
    'if (time_diff > tsig->fudge) {' \
    'if (false) {'

# Mutation 3: TSIG key name check
run_mutation "TSIG Key Name Check Bypass" "tsig.cpp" 274 \
    'if (dns_name_tolower(tsig->name) != dns_name_tolower(key->name)) {' \
    'if (false) {'

# Mutation 4: TSIG algorithm check
run_mutation "TSIG Algorithm Check Bypass" "tsig.cpp" 281 \
    'if (msg_algo != key->algorithm) {' \
    'if (false) {'

# Mutation 5: Single wildcard check
run_mutation "Single Wildcard Detection Broken" "query_processor.cpp" 17 \
    'if (query_rr->name.length() >= 2 && query_rr->name.substr(0, 2) == "*.") {' \
    'if (false) {'

# Mutation 6: Double wildcard check
run_mutation "Double Wildcard Detection Broken" "query_processor.cpp" 20 \
    'if (query_rr->name.length() >= 3 && query_rr->name.substr(0, 3) == "**.") {' \
    'if (false) {'

# Mutation 7: Single wildcard dot check
run_mutation "Single Wildcard Dot Check Broken" "query_processor.cpp" 46 \
    'if (prefix.find('\''.'\'') == string::npos) {' \
    'if (true) {'

# Mutation 8: Prerequisite name in use check
run_mutation "Prerequisites Name In Use Check Broken" "update_processor.cpp" 19 \
    'if (!zone.hasRecordWithName(prereq->name))' \
    'if (false)'

# Mutation 9: Prerequisite name not in use check
run_mutation "Prerequisites Name Not In Use Check Broken" "update_processor.cpp" 40 \
    'if (zone.hasRecordWithName(prereq->name))' \
    'if (false)'

# Mutation 10: Zone modified flag
run_mutation "Zone Modified Flag Not Set" "zone.cpp" 0 \
    'modified = true;' \
    'modified = false;'

echo "=== Summary ===" >> MUTATION_TESTING_REPORT.md
echo "" >> MUTATION_TESTING_REPORT.md
echo "Mutations that **SURVIVED** indicate gaps in test coverage." >> MUTATION_TESTING_REPORT.md
echo "Each survived mutation requires new tests to ensure the functionality is properly validated." >> MUTATION_TESTING_REPORT.md

cat MUTATION_TESTING_REPORT.md

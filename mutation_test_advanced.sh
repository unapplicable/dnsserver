#!/bin/bash

TIMEOUT=60
TEST_CMD="timeout ${TIMEOUT} make test"

echo "" >> MUTATION_TESTING_REPORT.md
echo "---" >> MUTATION_TESTING_REPORT.md
echo "" >> MUTATION_TESTING_REPORT.md
echo "## Advanced Mutations (Round 2)" >> MUTATION_TESTING_REPORT.md
echo "" >> MUTATION_TESTING_REPORT.md

run_mutation() {
    local name="$1"
    local file="$2"
    local old="$3"
    local new="$4"
    
    echo "Testing: $name"
    echo "### $name" >> MUTATION_TESTING_REPORT.md
    echo "**File:** \`$file\`" >> MUTATION_TESTING_REPORT.md
    
    # Create backup
    cp "$file" "$file.mutbak"
    
    # Apply mutation using perl for better control
    perl -i -pe "s/\Q$old\E/$new/" "$file"
    
    # Check if mutation was applied
    if diff -q "$file" "$file.mutbak" > /dev/null 2>&1; then
        echo "⚠️  **SKIPPED** - Pattern not found or no change" >> MUTATION_TESTING_REPORT.md
        mv "$file.mutbak" "$file"
        echo "" >> MUTATION_TESTING_REPORT.md
        echo "SKIPPED"
        return
    fi
    
    # Run tests
    if $TEST_CMD > /tmp/test_output.txt 2>&1; then
        echo "❌ **SURVIVED** - Tests passed with this bug!" >> MUTATION_TESTING_REPORT.md
        echo "" >> MUTATION_TESTING_REPORT.md
        echo '```' >> MUTATION_TESTING_REPORT.md
        echo "Original: $old" >> MUTATION_TESTING_REPORT.md
        echo "Mutated:  $new" >> MUTATION_TESTING_REPORT.md
        echo '```' >> MUTATION_TESTING_REPORT.md
        echo "" >> MUTATION_TESTING_REPORT.md
        echo "**Action:** Need additional test coverage" >> MUTATION_TESTING_REPORT.md
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

# Mutation 1: Return wrong HMAC algorithm
run_mutation "Wrong Default HMAC Algorithm" "tsig.cpp" \
    "return HMAC_SHA256; // Default" \
    "return HMAC_MD5; // MUTATION"

# Mutation 2: HMAC computation returns empty
run_mutation "HMAC Computation Returns Empty" "tsig.cpp" \
    "return string(reinterpret_cast<char*>(result), result_len);" \
    'return ""; // MUTATION'

# Mutation 3: Base64 decode returns empty
run_mutation "Base64 Decode Returns Empty" "tsig.cpp" \
    "return string(buffer, decoded_size);" \
    'return ""; // MUTATION'

# Mutation 4: Wrong zone name comparison
run_mutation "Zone Name Comparison Always True" "zone.cpp" \
    "return dns_name_tolower(zoneName) == dns_name_tolower(zone_name);" \
    "return true; // MUTATION"

# Mutation 5: TTL not copied in record
run_mutation "TTL Not Set in toString" "rr.cpp" \
    'ss << name << " " << ttl << " IN ";' \
    'ss << name << " " << 0 << " IN "; // MUTATION'

# Mutation 6: Wrong serial increment
run_mutation "Serial Incremented by Wrong Amount" "zone.cpp" \
    "currentSerial++;" \
    "currentSerial += 2; // MUTATION"

# Mutation 7: Modified flag not reset after save
run_mutation "Modified Flag Not Reset After Save" "zoneFileSaver.cpp" \
    "zone.resetModified();" \
    "// zone.resetModified(); // MUTATION"

# Mutation 8: Wildcard suffix comparison wrong
run_mutation "Wildcard Suffix Comparison Off-By-One" "query_processor.cpp" \
    "if (rr->name.length() > suffix.length() &&" \
    "if (rr->name.length() >= suffix.length() && // MUTATION"

# Mutation 9: ACL allows wrong IPs
run_mutation "ACL Allow Check Inverted" "acl.cpp" \
    "bool Acl::isAllowed(const string& ip) const {" \
    "bool Acl::isAllowed(const string& ip) const { return true; // MUTATION"

# Mutation 10: Zone file path not validated
run_mutation "Zone File Path Not Checked" "zone.cpp" \
    'if (filePath.empty()) return false;' \
    'if (false) return false; // MUTATION'

# Mutation 11: TSIG present but not required
run_mutation "TSIG Present But Not Required Fails" "tsig.cpp" \
    'if (!key) {' \
    'if (key) { // MUTATION'

# Mutation 12: Record type mismatch not checked
run_mutation "Record Type Mismatch Not Validated" "query_processor.cpp" \
    "if (query_rr->type == RR::TYPESTAR || rr->type == query_rr->type) {" \
    "if (true) { // MUTATION"

# Mutation 13: Zone authority check bypassed
run_mutation "Zone Authority Lookup Returns Null" "zone_authority.cpp" \
    "return zones[zone_name];" \
    "return NULL; // MUTATION"

# Mutation 14: Prerequisites class check wrong
run_mutation "Prerequisites Class Check Wrong" "update_processor.cpp" \
    "if (prereq->rrclass == RR::CLASSANY)" \
    "if (true) // MUTATION"

# Mutation 15: Response flags not set correctly
run_mutation "Response Flags Not Set" "query_processor.cpp" \
    "response.qr = 1;" \
    "response.qr = 0; // MUTATION"

echo "=== Final Summary ===" >> MUTATION_TESTING_REPORT.md
echo "" >> MUTATION_TESTING_REPORT.md
grep "SURVIVED" MUTATION_TESTING_REPORT.md | wc -l > /tmp/survived_count.txt
grep "KILLED" MUTATION_TESTING_REPORT.md | wc -l > /tmp/killed_count.txt
echo "- Mutations KILLED: $(cat /tmp/killed_count.txt)" >> MUTATION_TESTING_REPORT.md
echo "- Mutations SURVIVED: $(cat /tmp/survived_count.txt)" >> MUTATION_TESTING_REPORT.md
echo "" >> MUTATION_TESTING_REPORT.md

cat MUTATION_TESTING_REPORT.md

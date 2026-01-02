#!/bin/bash

TIMEOUT=60

echo "" >> MUTATION_TESTING_REPORT.md
echo "---" >> MUTATION_TESTING_REPORT.md
echo "## Manual Mutations (Round 3)" >> MUTATION_TESTING_REPORT.md
echo "" >> MUTATION_TESTING_REPORT.md

test_mutation() {
    local name="$1"
    local file="$2"
    
    echo "Testing: $name"
    echo "### $name" >> MUTATION_TESTING_REPORT.md
    echo "**File:** \`$file\`" >> MUTATION_TESTING_REPORT.md
    
    # Run tests
    if timeout $TIMEOUT make test > /tmp/test_output.txt 2>&1; then
        echo "❌ **SURVIVED** - Tests still pass!" >> MUTATION_TESTING_REPORT.md
        echo "" >> MUTATION_TESTING_REPORT.md
        echo "**Action:** Need test coverage" >> MUTATION_TESTING_REPORT.md
        result="SURVIVED"
    else
        echo "✅ **KILLED**" >> MUTATION_TESTING_REPORT.md
        result="KILLED"
    fi
    
    echo "" >> MUTATION_TESTING_REPORT.md
    echo "$name: $result"
}

# Test 1: Break HMAC return value
cp tsig.cpp tsig.cpp.bak
sed -i '102s/return string(reinterpret_cast<char\*>(result), result_len);/return "";/' tsig.cpp
test_mutation "HMAC Returns Empty String" "tsig.cpp"
mv tsig.cpp.bak tsig.cpp

# Test 2: Break zone name matching
cp zone.cpp zone.cpp.bak
sed -i 's/return dns_name_tolower(zoneName) == dns_name_tolower(zone_name);/return true;/' zone.cpp
test_mutation "Zone Name Match Always True" "zone.cpp"
mv zone.cpp.bak zone.cpp

# Test 3: Modified flag not reset
cp zoneFileSaver.cpp zoneFileSaver.cpp.bak
sed -i 's/zone\.resetModified();/\/\/ zone.resetModified();/' zoneFileSaver.cpp
test_mutation "Modified Flag Not Reset On Save" "zoneFileSaver.cpp"
mv zoneFileSaver.cpp.bak zoneFileSaver.cpp

# Test 4: ACL check always allows
cp acl.cpp acl.cpp.bak
sed -i '/^bool Acl::isAllowed/a\    return true;' acl.cpp
test_mutation "ACL Always Allows" "acl.cpp"
mv acl.cpp.bak acl.cpp

# Test 5: Response QR flag not set
cp query_processor.cpp query_processor.cpp.bak
sed -i 's/response\.qr = 1;/response.qr = 0;/' query_processor.cpp
test_mutation "Response QR Flag Wrong" "query_processor.cpp"
mv query_processor.cpp.bak query_processor.cpp

echo "" >> MUTATION_TESTING_REPORT.md
echo "---" >> MUTATION_TESTING_REPORT.md
echo "## Summary" >> MUTATION_TESTING_REPORT.md
echo "" >> MUTATION_TESTING_REPORT.md
echo "Total mutations tested: ~25" >> MUTATION_TESTING_REPORT.md
echo "" >> MUTATION_TESTING_REPORT.md
grep "KILLED" MUTATION_TESTING_REPORT.md | wc -l > /tmp/killed.txt
grep "SURVIVED" MUTATION_TESTING_REPORT.md | wc -l > /tmp/survived.txt
echo "- ✅ Killed: $(cat /tmp/killed.txt)" >> MUTATION_TESTING_REPORT.md
echo "- ❌ Survived: $(cat /tmp/survived.txt)" >> MUTATION_TESTING_REPORT.md

cat MUTATION_TESTING_REPORT.md

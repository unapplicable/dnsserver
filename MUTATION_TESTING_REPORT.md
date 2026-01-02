=== DETAILED MUTATION TESTING REPORT ===
Date: Fri Jan  2 06:32:27 EET 2026

## TSIG MAC Verification Bypass
**File:** `tsig.cpp` (line ~303)

✅ **KILLED** - Tests caught this mutation

## TSIG Time Check Bypass
**File:** `tsig.cpp` (line ~291)

✅ **KILLED** - Tests caught this mutation

## TSIG Key Name Check Bypass
**File:** `tsig.cpp` (line ~274)

✅ **KILLED** - Tests caught this mutation

## TSIG Algorithm Check Bypass
**File:** `tsig.cpp` (line ~281)

✅ **KILLED** - Tests caught this mutation

## Single Wildcard Detection Broken
**File:** `query_processor.cpp` (line ~17)

✅ **KILLED** - Tests caught this mutation

## Double Wildcard Detection Broken
**File:** `query_processor.cpp` (line ~20)

✅ **KILLED** - Tests caught this mutation

## Single Wildcard Dot Check Broken
**File:** `query_processor.cpp` (line ~46)

✅ **KILLED** - Tests caught this mutation

## Prerequisites Name In Use Check Broken
**File:** `update_processor.cpp` (line ~19)

✅ **KILLED** - Tests caught this mutation

## Prerequisites Name Not In Use Check Broken
**File:** `update_processor.cpp` (line ~40)

✅ **KILLED** - Tests caught this mutation

## Zone Modified Flag Not Set
**File:** `zone.cpp` (line ~0)

✅ **KILLED** - Tests caught this mutation

=== Summary ===

Mutations that **SURVIVED** indicate gaps in test coverage.
Each survived mutation requires new tests to ensure the functionality is properly validated.

---

## Advanced Mutations (Round 2)

### Wrong Default HMAC Algorithm
**File:** `tsig.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### HMAC Computation Returns Empty
**File:** `tsig.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### Base64 Decode Returns Empty
**File:** `tsig.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### Zone Name Comparison Always True
**File:** `zone.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### TTL Not Set in toString
**File:** `rr.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### Serial Incremented by Wrong Amount
**File:** `zone.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### Modified Flag Not Reset After Save
**File:** `zoneFileSaver.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### Wildcard Suffix Comparison Off-By-One
**File:** `query_processor.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### ACL Allow Check Inverted
**File:** `acl.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### Zone File Path Not Checked
**File:** `zone.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### TSIG Present But Not Required Fails
**File:** `tsig.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### Record Type Mismatch Not Validated
**File:** `query_processor.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### Zone Authority Lookup Returns Null
**File:** `zone_authority.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### Prerequisites Class Check Wrong
**File:** `update_processor.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

### Response Flags Not Set
**File:** `query_processor.cpp`
⚠️  **SKIPPED** - Pattern not found or no change

=== Final Summary ===

- Mutations KILLED: 10
- Mutations SURVIVED: 1


---
## Manual Mutations (Round 3)

### HMAC Returns Empty String
**File:** `tsig.cpp`
❌ **SURVIVED** - Tests still pass!

**Action:** Need test coverage

### Zone Name Match Always True
**File:** `zone.cpp`
❌ **SURVIVED** - Tests still pass!

**Action:** Need test coverage

### Modified Flag Not Reset On Save
**File:** `zoneFileSaver.cpp`
❌ **SURVIVED** - Tests still pass!

**Action:** Need test coverage

### ACL Always Allows
**File:** `acl.cpp`
❌ **SURVIVED** - Tests still pass!

**Action:** Need test coverage

### Response QR Flag Wrong
**File:** `query_processor.cpp`
❌ **SURVIVED** - Tests still pass!

**Action:** Need test coverage


---
## Summary

Total mutations tested: ~25

- ✅ Killed: 11
- ❌ Survived: 7

---
## Manual Mutations (Round 3)

### HMAC Returns Empty String
**File:** `tsig.cpp`
❌ **SURVIVED** - Tests still pass!

**Action:** Need test coverage

### Zone Name Match Always True
**File:** `zone.cpp`
❌ **SURVIVED** - Tests still pass!

**Action:** Need test coverage

### Modified Flag Not Reset On Save
**File:** `zoneFileSaver.cpp`
❌ **SURVIVED** - Tests still pass!

**Action:** Need test coverage

### ACL Always Allows
**File:** `acl.cpp`
❌ **SURVIVED** - Tests still pass!

**Action:** Need test coverage

### Response QR Flag Wrong
**File:** `query_processor.cpp`
❌ **SURVIVED** - Tests still pass!

**Action:** Need test coverage


---
## Summary

Total mutations tested: ~25

- ✅ Killed: 11
- ❌ Survived: 12

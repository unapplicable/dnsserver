---
id: 043fea90-2f88-46c6-9996-27068316234f
created: '2026-04-06T21:06:51.461Z'
modified: '2026-04-06T21:06:51.461Z'
memory_type: learning
tags: []
---
# Important Bugs and Lessons Learned

## Compression Loop Detection Bug
**Bug:** Bit array sized incorrectly - 8192 bits (1KB) instead of 65536 bits (8KB)
**Impact:** Only tracked first 8KB of packet, compression at higher offsets bypassed detection
**Fix:** Changed `MAX_VISITED = 8192` (bits) to `MAX_VISITED_BYTES = 8192` (bytes)
**Lesson:** Always verify array size calculations match intended coverage

---

## DNS UPDATE Unpacking Bug (234c651)
**Bug:** RDLEN=0 not handled for PTR, CNAME, NS, MX, SOA records
**Fix:** Handle zero-length RDATA correctly in message.cpp

---

## Zone Name Inheritance (328937e)
**Bug:** Zone file name not properly inherited to child records
**Fix:** Correct zone name propagation in zoneFileLoader

---

## RR Type Subclass Creation (b40218e)
**Bug:** RR unpacking created wrong typed subclasses
**Fix:** Virtual clone() method in base RR class

---

## TXT Record Parsing (c32b258)
**Bug:** Interpreting dots as separators in TXT record values
**Fix:** Don't treat TXT value as a domain name

---

## Integration Test Issues (de775bb)
**Bug:** Server lifecycle not properly managed in tests
**Fix:** Better process cleanup with trap handlers

---

## Constant-Time Comparison (eaf01f2)
**Bug:** Using std::string::operator!= for MAC comparison (timing attackable)
**Fix:** CRYPTO_memcmp for constant-time comparison

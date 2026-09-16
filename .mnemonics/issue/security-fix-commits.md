---
id: 2e10637f-b23c-477a-a5f0-8893de0dca6d
created: '2026-04-06T21:06:35.072Z'
modified: '2026-04-06T21:06:35.072Z'
memory_type: issue
tags: []
---
# Key Security Fixes in Git History

## 1. DNS Compression Loop Vulnerability (69dbf73)
**Issue:** Infinite loop DoS - single 19-byte UDP packet could hang server
**Fix:** 
- Bit array tracking for visited offsets (8KB for full 64KB packet coverage)
- MAX_JUMPS=64 limit to prevent deep nesting
- Bounds checking for pointers beyond packet length
- RFC 1035 max name length (255 bytes) enforcement

**Timeline:** Fixed Jan 2026, then fixed bit array sizing bug (was only 1KB, needs 8KB for full coverage)

---

## 2. TCP DoS Mitigation (fd113ca)
**Issue:** Slowloris attack - attackers holding TCP connections open indefinitely
**Fix:** 
- SO_RCVTIMEO socket timeout (10 seconds)
- Timeout on both length prefix and message body reads
- Cross-platform (Linux/Windows)
- Detailed timeout logging

---

## 3. TSIG Timing Attack (eaf01f2)
**Issue:** std::string::operator!= could leak MAC bytes via response timing
**Fix:** CRYPTO_memcmp for constant-time MAC comparison
**Status:** Prevents byte-by-byte MAC forgery attacks

---

## 4. ACL Silent Drop (1512c2d)
**Issue:** Queries denied by ACL were silently dropped (no response)
**Fix:** Return REFUSED (RCode 5) per RFC 1035

---

## 5. Additional Security Improvements
- RFC 2136 error codes for UPDATE prerequisite failures
- NXDOMAIN responses include SOA per RFC 2308
- Graceful degradation on zone file parse failures
- RAII MutexGuard for exception-safe locking
- memcpy for wire-format reads (avoid C-style casts)

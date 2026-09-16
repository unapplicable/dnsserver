---
id: eb90d8f6-aa12-4eb3-a8ec-aa642e6e9d1f
created: '2026-04-06T21:02:35.764Z'
modified: '2026-04-06T21:02:35.764Z'
memory_type: issue
tags: []
---
# Known Security Issues and Mitigations

## Fixed Security Issues

### 1. DNS Compression Loop Vulnerability
- **Issue:** Malformed DNS packets could cause infinite loop in compression handling
- **Location:** message.cpp, rr.cpp
- **Fix:** Added protection in DNSParseException class with jump counter limit
- **Status:** FIXED

### 2. TCP DoS Mitigation
- **Issue:** No protection against slow TCP connection attacks
- **Location:** dnsserver.cpp
- **Mitigation:** Implemented TCP timeout (60s default), connection limits
- **Status:** FIXED

### 3. TSIG Implementation
- **Status:** Uses C++ std::string for all TSIG fields (no buffer overflow)
- **Future:** Response signing not yet implemented (avoiding CVE-2017-3142/3143)
- **Key Storage:** In-memory (configured per-zone)

### 4. ACL Longest-Match
- **Issue:** ACL lookup wasn't using longest-prefix match
- **Fix:** Implemented longest-match algorithm in acl.cpp
- **Status:** FIXED

## Known Limitations
- No response signing for TSIG (future feature)
- In-memory key storage (no persistent key database)
- No DNSSEC support
- No recursion (authoritative-only)

## Signal Handling
- SIGHUP: Zone reload (via g_reload_zones flag)
- SIGTERM: Graceful shutdown (via g_shutdown flag)

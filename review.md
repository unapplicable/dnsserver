# Code Review: DNS Server

Date: 2026-03-29
Scope: Design, Reliability, Security, Observability

---

## Architecture Summary

C++ authoritative DNS server implementing QUERY (opcode 0), UPDATE (opcode 5, RFC 2136),
EDNS(0) (RFC 6891), TSIG authentication (RFC 2845), and split-horizon DNS via ACLs.
Single-threaded `select()` event loop with background auto-save thread. UDP + TCP on IPv4/IPv6.

### Request Flow

```
UDP/TCP packet -> serverloop() -> handle()
  -> Message::unpack()
  -> if QUERY:  handleQuery() -> ZoneAuthority::findZoneForName()
                  -> QueryProcessor::findMatches() -> Message::pack() -> send
  -> if UPDATE: handleUpdate() -> ZoneAuthority::findZoneForName()
                  -> TSIG::verify() -> UpdateProcessor::checkPrerequisites()
                  -> UpdateProcessor::applyUpdates() (mutex-protected)
                  -> Message::pack() -> send
```

---

## Design

1. **Static-only utility classes** (`TSIG`, `UpdateProcessor`, `QueryProcessor`, `ZoneFileLoader`)
   are C-style modules pretending to be classes. Consider free functions in a namespace.
2. **C-style casts** for wire-format reads (`(unsigned short&)data[offset]`) violate strict
   aliasing — undefined behavior. Use `memcpy` instead.
3. **`goto send_response`** in `handleUpdate()` is fragile. Use RAII or early-return patterns.
4. **Raw `new`/`delete` everywhere** — no smart pointers. Exception paths can leak.
5. **`unsigned long` for IPv4 addresses** in ACL — 32-bit only, breaks IPv6 ACL support.
6. **Duplicate exception handling** — `handleQuery()`/`handleUpdate()` catch and re-throw,
   then `handle()` catches again. Let exceptions propagate to one place.
7. **Hardcoded 10-min TTL** in query responses — ignores zone file TTLs.
8. **CMakeLists.txt is non-functional** — only compiles stub `main.cpp`.
9. **DYNAMIC records read files on every query** — no caching layer.

## Reliability

1. **Data race on zone reads** — autosave thread reads `zone->modified` outside mutex lock,
   while main thread writes it under mutex. Queries read `zone->rrs` without lock while
   updates mutate it. Use-after-free risk.
2. **No RAII for mutex** — manual `pthread_mutex_lock`/`unlock`. A `goto` or exception
   between lock and unlock can skip release.
3. **ACL sub-zone memory leak** — `Acl::~Acl()` is empty; `Zone*` objects in entries
   are never freed.
4. **Blocking TCP** — `recv()` on main thread blocks all UDP processing during slow clients.
5. **Zone file parse failure kills the server** — no graceful degradation.
6. **Inconsistent DNS error codes** — all prerequisite failures return NXDOMAIN (3), but
   RFC 2136 specifies NXRRSET (8), YXDOMAIN (6), NOTZONE (10).
7. **Silent drops on ACL deny** — client gets no DNS response at all.
8. **No SOA in NXDOMAIN responses** — RFC 2308 requires it for negative caching.
9. **`select()` limit** — FD_SETSIZE (1024) caps concurrent sockets.

## Security

1. **No constant-time MAC comparison** — `std::string::operator!=` for TSIG verification
   enables timing attacks. Use `CRYPTO_memcmp`.
2. **No TSIG response signing** — responses are unsigned.
3. **No rate limiting** — no per-IP query/connection rate limiting.
4. **Plaintext secrets in zone files** — TSIG keys stored as-is.
5. **No replay protection** — TSIG messages can be replayed within 300s fudge window.
6. **HMAC-MD5 still available** — weak algorithm.
7. **No DNSSEC** support.

## Observability

1. **No structured logging** — free-text to `cerr`/`cout`.
2. **No log levels** — cannot reduce verbosity.
3. **Mixed stdout/stderr** — confusing for operators.
4. **No metrics** — no counters for qps, errors, latency.
5. **No query audit trail** for UPDATEs with source IP / identity.

---

## Priority Fixes

| Priority | Issue | Fix |
|----------|-------|-----|
| Critical | TSIG timing attack | `CRYPTO_memcmp` for MAC comparison |
| Critical | Data race on `zone->modified` | Move `modified` check inside mutex in autosave thread |
| High | Strict aliasing UB | Replace `(unsigned short&)` casts with `memcpy` |
| High | Manual mutex lock/unlock | `std::lock_guard<pthread_mutex_t>` RAII wrapper |
| High | ACL sub-zone leak | Delete `Zone*` entries in `~Acl()` |
| High | Zone parse crash | Catch and log parse errors, continue with remaining zones |

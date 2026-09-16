---
id: 2018c482-1e6f-445b-9029-0f399266061f
created: '2026-04-06T21:02:41.149Z'
modified: '2026-04-06T21:02:41.149Z'
memory_type: design-decision
tags: []
---
# Design Decisions

## Thread Safety
- Global mutex (g_zone_mutex) protects zone modifications
- pthread_mutex_t with PTHREAD_MUTEX_INITIALIZER
- Signal handlers use volatile sig_atomic_t (g_reload_zones, g_shutdown)

## Zone Management
- Zone contains: name, filename, auto_save flag, modified flag, ACL, TSIG key, parent pointer
- Multiple zones supported with ZoneAuthority for lookup
- Zone hierarchy via parent pointer for ACL sub-zones
- Modified zones auto-save on update

## Message Handling
- Opcode: QUERY(0), IQUERY(1), STATUS(2), UPDATE(5)
- RCode: Standard DNS codes + YXDOMAIN, YXRRSET, NXRRSET, NOTZONE (RFC 2136)
- EDNS(0) copied from request to response via copyEDNS()
- OPT record retrieved via getOPT()

## RR Type System
- Base RR class with virtual pack()/unpack()
- Type-specific subclasses: RRA, RRAAAA, RRCNAME, RRMX, RRNS, RRSOA, RRTXT, etc.
- DYNAMIC records for ACME challenges
- TSIG records for authentication

## ACL System
- Supports IP/CIDR notation
- Longest-match prefix selection
- Per-zone ACL configuration
- Unauthorized queries return REFUSED

## Query Processing Flow
1. Parse DNS message
2. Check ACL (return REFUSED if unauthorized)
3. Find zone via ZoneAuthority
4. Process query/update via QueryProcessor/UpdateProcessor
5. Pack and send response

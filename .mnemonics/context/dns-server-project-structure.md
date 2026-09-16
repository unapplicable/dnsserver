---
id: be6759fe-50a3-449f-802f-2288e298415f
created: '2026-04-06T21:02:20.639Z'
modified: '2026-04-06T21:02:20.639Z'
memory_type: context
tags: []
---
# DNS Server Project Overview

## Project Type
Authoritative DNS server with dynamic update support (RFC 2136)

## Language & Build
- Language: C++14 (Makefile) / C++20 (CMakeLists.txt placeholder)
- Build: Makefile with clang++ (primary), CMake (experimental stub)
- Dependencies: OpenSSL, pthreads

## Key Components
- **dnsserver.cpp** - Main server with query/update handling (1023 lines)
- **message.h/cpp** - DNS message parsing and construction
- **zone.h/cpp** - Zone data management with ACL support
- **rr.h/cpp** - Resource record base class
- **rr*.cpp** - Specific RR types: A, AAAA, CNAME, MX, NS, SOA, TXT, TXT, DHCPID, OPT, TSIG, DYNAMIC
- **acl.h/cpp** - Access control list with longest-match support
- **zoneFileLoader.cpp** - Zone file parsing
- **zoneFileSaver.cpp** - Zone persistence
- **query_processor.cpp** - Query processing logic
- **update_processor.cpp** - Dynamic updates (RFC 2136)
- **zone_authority.cpp** - Zone lookup and authority determination
- **tsig.cpp** - TSIG authentication for dynamic updates

## Supported DNS Features
- Standard query types (A, AAAA, CNAME, MX, NS, SOA, TXT, etc.)
- Dynamic updates with TSIG authentication
- EDNS(0) support
- AXFR/IXFR (zone transfers)
- Wildcard record matching
- Multiple zone support with ACLs
- SIGHUP zone reloading
- Zone file autosave on modifications
- TCP connection handling with timeout protection
- CHAOS class version.bind queries

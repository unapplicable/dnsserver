---
id: c8118127-5065-4bb5-aac2-169a0d1bf982
created: '2026-04-06T21:02:31.690Z'
modified: '2026-04-06T21:02:31.690Z'
memory_type: context
tags: []
---
# DNS Server Test Infrastructure

## Test Framework
- Uses Catch2 for unit testing
- Custom shell scripts for integration tests

## Test Files and Their Purposes

### Unit Tests
- **test_acl.cpp** - ACL functionality tests
- **test_acl_longest_match.cpp** - ACL longest-prefix matching
- **test_acl_query.cpp** - ACL query processing
- **test_acl_unauthorized.cpp** - ACL authorization checks
- **test_dns_update.cpp** - Dynamic update processing (major test file, ~1800+ lines)
- **test_edns.cpp** - EDNS(0) support
- **test_query_processor.cpp** - Query processing logic
- **test_rr_roundtrip.cpp** - RR wire format roundtrip
- **test_rr_types.cpp** - Individual RR type parsing
- **test_sighup_unit.cpp** - SIGHUP reload functionality
- **test_tsig.cpp** - TSIG authentication
- **test_tsig_hmac.cpp** - TSIG HMAC verification
- **test_zone_matching.cpp** - Zone matching logic
- **test_zone_roundtrip.cpp** - Zone file parsing roundtrip

### Integration Test Scripts
- **run_all_tests.sh** - Master test runner
- **test_update.sh** - Dynamic update tests
- **test_dynamic.sh** - Dynamic record tests
- **test_edns_integration.sh** - EDNS integration
- **test_sighup.sh** - SIGHUP reload tests
- **test_tcp_timeout.sh** - TCP timeout protection
- **test_tsig.sh** - TSIG integration
- **test_wildcard_simple.sh** - Wildcard matching
- **test_autosave_daemon.sh** - Zone autosave daemon mode

## Test Ports
- 5353 - Default port
- 15353, 15354 - Test ports
- 15500 - Autosave tests

## Test Zone Files
- test_zone1.zone, test_zone2.zone - Basic zone files
- test_update.zone - Update testing
- test_edns.zone - EDNS testing
- test_tsig.zone - TSIG testing
- test_wildcard.zone - Wildcard testing
- test_dynamic.zone - Dynamic records
- test_autosave.zone - Autosave testing

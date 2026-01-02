# DNS Wildcard Prefix Query Implementation

## Overview
This implementation adds support for wildcard prefix queries in the DNS server, allowing clients to query for multiple records matching a pattern.

## Features

### Single Wildcard (`*.domain.com`)
Matches all **immediate** subdomains of the specified domain.

**Example:**
- Query: `*.foo.com` with type `A`
- Matches: `a.foo.com`, `b.foo.com`, `server.foo.com`
- Does NOT match: `x.y.foo.com`, `a.b.c.foo.com` (nested subdomains)

### Double Wildcard (`**.domain.com`)
Matches **all** subdomains of the specified domain, regardless of nesting depth.

**Example:**
- Query: `**.foo.com` with type `A`
- Matches: `a.foo.com`, `x.y.foo.com`, `a.b.c.foo.com`, etc.

## Implementation Details

### Modified Files
1. **query_processor.cpp** - Core wildcard matching logic
   - Detects `*.` and `**.` prefixes in query names
   - Filters records by suffix matching
   - For single wildcard: checks that prefix contains no dots (immediate subdomain)
   - For double wildcard: matches any subdomain depth
   - Respects record type filtering (A, AAAA, etc.)

2. **test_query_processor.cpp** - Unit tests
   - `test_single_wildcard_prefix()` - Tests `*.foo.com` matching
   - `test_double_wildcard_prefix()` - Tests `**.foo.com` matching
   - `test_wildcard_with_typestar()` - Tests wildcard with any record type
   - `test_wildcard_no_matches()` - Tests empty result sets

3. **test_wildcard_simple.sh** - Integration tests
   - Tests wildcard queries against live DNS server
   - Validates record counts and exact match behavior
   - Ensures backward compatibility with exact queries

## Usage Examples

### Using dig:
```bash
# Query all immediate A records under example.com
dig @server *.example.com A

# Query all nested A records under example.com
dig @server **.example.com A

# Query all immediate AAAA records under example.com
dig @server *.example.com AAAA

# Works with any record type
dig @server *.example.com MX
```

### Behavior:
Given zone records:
```
a.example.com.        IN A     10.0.1.1
b.example.com.        IN A     10.0.1.2
x.y.example.com.      IN A     10.0.2.1
a.b.c.example.com.    IN A     10.0.2.2
```

Queries:
- `*.example.com A` → Returns: 10.0.1.1, 10.0.1.2
- `**.example.com A` → Returns: 10.0.1.1, 10.0.1.2, 10.0.2.1, 10.0.2.2

## Testing

### Unit Tests
```bash
make test
```
Runs all unit tests including wildcard functionality tests.

### Integration Tests
```bash
make test-integration
```
Runs integration tests against a live DNS server instance.

### Full Test Suite
```bash
make test-all
```
Runs both unit and integration tests.

## Performance Considerations
- Wildcard queries scan all records in the zone
- Performance is O(n) where n is the number of records in the zone
- For large zones, consider indexing or caching strategies
- Type filtering reduces the number of returned records

## Backward Compatibility
- All existing exact name queries work unchanged
- Standard DNS wildcard records (RFC 4592) are unaffected
- No changes to zone file format or loading
- Existing test suites continue to pass

## Standards Compliance
Note: This implementation adds a custom query extension for operational convenience. It is NOT part of standard DNS RFCs. The `*.` and `**.` prefixes in query names are extensions specific to this server implementation.

## Future Enhancements
Possible improvements:
- Add query result pagination for large result sets
- Implement caching for common wildcard patterns
- Add zone-level configuration to enable/disable wildcards
- Support for more complex patterns (e.g., regex)

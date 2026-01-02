# Zone Matching Fix - Most Specific Zone Selection

## Problem

When multiple zones were configured (e.g., `example.com` and `s6.example.com`), queries for records in the more specific zone (`s6.example.com`) were incorrectly matching the parent zone (`example.com`) first, preventing proper zone-specific record resolution.

### Example of the Issue

With zones:
- `example.com` 
- `s6.example.com`

A query for `www.s6.example.com` would match `example.com` zone (incorrect) instead of the more specific `s6.example.com` zone (correct).

## Root Cause

The `ZoneAuthority::findZoneForName()` function returned the **first matching zone** rather than the **most specific (longest) matching zone**. This violated the DNS standard behavior where the most specific zone should always be selected.

## Solution

Modified `zone_authority.cpp` to implement **longest-match zone selection**:

1. Iterate through all zones and find ALL matching zones
2. Track the longest matching zone (by zone name length)
3. Return the most specific zone

This ensures that:
- `s6.example.com` queries match the `s6.example.com` zone
- `example.com` queries match the `example.com` zone  
- Zone order in configuration doesn't matter

## Testing

Added comprehensive unit tests in `test_zone_matching.cpp`:
- Most specific zone wins (forward zones)
- Reverse zone specificity (PTR zones)
- Zone order independence
- Case insensitive matching

All tests pass successfully.

## Deployment

After deploying the fixed binary, restart the DNS server:
```bash
sudo systemctl restart dnsserver.service
```

Then verify with:
```bash
dig @10.222.1.1 s6.example.com SOA
dig @10.222.1.1 www.s6.example.com A
```

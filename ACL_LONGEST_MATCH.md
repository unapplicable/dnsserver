# ACL Longest-Prefix Matching Implementation

## Overview

Implemented longest-prefix (most specific) matching for ACL subnet selection in DNS queries. When multiple ACL entries match a client IP address, the ACL with the longest subnet mask (most specific match) is selected.

## Implementation Details

### Core Logic

**Location:** `acl.cpp` - `Acl::findMostSpecificMatch()`

```cpp
Zone* Acl::findMostSpecificMatch(unsigned long client_ip) const
{
	Zone* best_match = NULL;
	unsigned long best_mask = 0;
	
	for (vector<AclEntry>::const_iterator it = entries.begin(); it != entries.end(); ++it)
	{
		if (it->subnet.match(client_ip))
		{
			unsigned long current_mask = ntohl(it->subnet.getMask());
			if (current_mask > best_mask)
			{
				best_mask = current_mask;
				best_match = it->zone;
			}
		}
	}
	
	return best_match;
}
```

### Query Processing Integration

**Location:** `zone_authority.cpp` - `ZoneAuthority::findZoneForName()`

When processing a DNS query:
1. Find the most specific zone for the query name (longest domain match)
2. If that zone has ACLs, find the most specific ACL match for the client IP
3. Use the ACL sub-zone if found, otherwise deny access (if ACL present but no match) or use parent zone (if no ACL)
4. Return records from the selected zone

```cpp
// Check ACL if present - use longest match
if (best_match->acl && best_match->acl->size() > 0)
{
	Zone* acl_zone = best_match->acl->findMostSpecificMatch(client_addr);
	if (acl_zone)
	{
		// Found matching ACL entry - use its zone
		result.authorized = true;
		result.zone = acl_zone;
		return result;
	}
	
	// ACL present but no match - deny access
	result.authorized = false;
	result.error_message = "Access denied by ACL";
	return result;
}
else
{
	// No ACL - allow access to parent zone
	result.authorized = true;
	result.zone = best_match;
	return result;
}
```

## Behavior

### Matching Rules

- **Most Specific Wins:** Among all matching ACL entries, the one with the longest prefix length (highest mask value) is selected
- **No Match:** If no ACL matches the client IP, the parent zone is used
- **Tie Breaking:** If multiple ACLs have the same mask length (shouldn't happen in practice), the first one added wins

### Example Scenarios

#### Scenario 1: Nested Subnets

Zone `example.com.` has three ACL entries:
- `10.0.0.0/8` → ACL Zone A
- `10.1.0.0/16` → ACL Zone B
- `10.1.1.0/24` → ACL Zone C

Query from `10.1.1.50`:
- Matches all three subnets
- `/24` is most specific → **ACL Zone C is used**

Query from `10.1.5.50`:
- Matches `/8` and `/16`
- `/16` is most specific → **ACL Zone B is used**

Query from `10.5.5.50`:
- Matches only `/8`
- → **ACL Zone A is used**

Query from `192.168.1.1`:
- Matches no ACL
- → **Parent zone is used**

#### Scenario 2: Non-Overlapping Subnets

Zone `test.com.` has two ACL entries:
- `192.168.1.0/24` → ACL Zone X
- `192.168.2.0/24` → ACL Zone Y

Query from `192.168.1.100`:
- Matches only first subnet → **ACL Zone X is used**

Query from `192.168.2.100`:
- Matches only second subnet → **ACL Zone Y is used**

#### Scenario 3: Conflicting Records

Parent zone and ACL zones can have records with the same name:
- Parent zone: `server.test.com. A 192.168.1.1`
- ACL zone (for `10.0.0.0/8`): `server.test.com. A 10.0.0.1`

Query from `10.5.5.5` returns `10.0.0.1` (ACL zone record)
Query from `192.168.1.1` returns `192.168.1.1` (parent zone record)

## Use Cases

### Network Segmentation

Provide different DNS responses based on network location:
- Internal network (`10.0.0.0/8`) sees internal IPs
- DMZ network (`192.168.1.0/24`) sees DMZ IPs  
- VPN users (`192.168.100.0/24`) see VPN-specific IPs

### Split-Horizon DNS

Serve different records to different clients without running multiple DNS servers:
- Office network sees internal services
- Remote workers see cloud-hosted services
- Public internet sees public-facing services

### Security & Access Control

Restrict certain records to specific networks:
- Admin interfaces only visible from management subnet
- Development resources only accessible from dev network
- Production services have tighter access controls

## Testing

### Unit Tests

**File:** `test_acl_longest_match.cpp`

Three comprehensive test suites:

1. **testAclLongestMatch():** Verifies longest-prefix selection with overlapping `/24`, `/28`, and `/30` subnets
2. **testAclConflictingRecords():** Confirms parent and ACL zones can have conflicting records  
3. **testMultipleOverlappingAcls():** Tests overlapping `/8`, `/16`, and `/24` subnets

All tests verify:
- Correct zone selection for various IPs
- NULL return when no ACL matches
- Independent record storage in parent vs ACL zones

### Running Tests

```bash
make test                    # Runs all unit tests including ACL longest match
./bin/test_acl_longest_match # Run ACL longest match tests only
```

## Performance Considerations

- **Linear Search:** Current implementation iterates through all ACL entries
- **Complexity:** O(n) where n = number of ACL entries per zone
- **Optimization Potential:** Could use prefix tree (trie) for large ACL lists, but current implementation is sufficient for typical use cases (< 100 ACL entries per zone)

## Backwards Compatibility

- Existing zones without ACLs work identically
- Existing ACL configurations continue to work
- The change only affects behavior when multiple ACL entries match the same client IP

## Future Enhancements

Potential improvements:
- IPv6 support for ACL matching
- Metric/logging for ACL match statistics
- Configuration option to control ACL matching behavior
- Support for ACL priority/weight beyond prefix length

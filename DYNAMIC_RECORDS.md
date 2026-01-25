# Dynamic DNS Records for ACME Challenges

## Overview

The DNS server now supports **dynamic TXT records** via the `$DYNAMIC` directive in zone files. This feature is designed for ACME (Automatic Certificate Management Environment) challenges but can be used for any scenario where DNS TXT records need to be updated frequently without reloading the entire zone.

## How It Works

Instead of storing static TXT records in the zone file, you can specify a file path that will be read on each DNS query. The file contents are returned as TXT records.

### Key Features

1. **Real-time updates**: File is read on every query, so changes take effect immediately
2. **Multiple records**: Each line in the file becomes a separate TXT record
3. **Deduplication**: Duplicate lines are automatically removed
4. **Sorted output**: Records are returned in sorted order
5. **Graceful failure**: If the file doesn't exist or is empty, no records are returned (NOERROR with 0 answers)

## Syntax

In your zone file, use the `$DYNAMIC` directive:

```
$DYNAMIC <name> <filepath>
```

### Example

```dns
$ORIGIN example.com.
@ 3600 IN SOA ns1.example.com. admin.example.com. 2024012501 3600 1800 604800 86400
@ 3600 IN NS ns1.example.com.
ns1 3600 IN A 192.0.2.1

; Dynamic record for ACME challenge
$DYNAMIC _acme-challenge.example.com. /var/acme/challenge.txt

; You can have multiple dynamic records
$DYNAMIC _acme-challenge.www.example.com. /var/acme/www-challenge.txt
```

## File Format

The file should contain one challenge token per line. Empty lines and whitespace are automatically trimmed.

**Example `/var/acme/challenge.txt`:**
```
challenge-token-abc123
challenge-token-def456
```

## Usage with ACME / Let's Encrypt

When using dns-01 challenge with ACME clients:

1. Configure your zone file with `$DYNAMIC` directive pointing to a challenge file
2. Configure your ACME client (certbot, acme.sh, etc.) to write challenge tokens to that file
3. The DNS server will automatically serve the updated challenges on the next query

### Example with acme.sh

```bash
# In your zone file:
# $DYNAMIC _acme-challenge.example.com. /var/acme/challenge.txt

# When acme.sh writes a challenge:
echo "challenge-token-from-acme" > /var/acme/challenge.txt

# Test it:
dig @your-dns-server _acme-challenge.example.com TXT +short
# Returns: "challenge-token-from-acme"
```

## Comparison with acmeshit.py

This implementation is inspired by the `acmeshit.py` script but integrated directly into the DNS server:

### acmeshit.py approach:
- Separate Python process running dnslib
- Reads file on each query
- Returns all lines as TXT records with TTL=1

### dnsserver $DYNAMIC approach:
- Integrated into main DNS server
- Same file-reading behavior
- Returns unique, sorted TXT records with TTL=1
- Part of regular zone management
- No need for separate process

## Performance Considerations

- File is read on **every query**, which is intentional for ACME use cases
- For high-traffic scenarios, consider:
  - Using filesystem caching (files in `/tmp` or tmpfs)
  - Keep challenge files small (typically 1-3 lines)
  - Use specific names like `_acme-challenge` to limit query volume

## Technical Details

- Dynamic records have RR type `DYNAMIC (65280)`
- When queried for TXT, they resolve to actual TXT records on-the-fly
- Records are created per-query and cleaned up after response
- The underlying DYNAMIC RR is never sent in DNS responses
- TTL is set to 1 second (like acmeshit.py)

## Limitations

1. Only works for TXT records (which is perfect for ACME)
2. File must be readable by the DNS server process
3. Maximum line length: 2000 characters (standard file read limit)
4. File I/O happens on every query (by design for real-time updates)

## Security Considerations

- Ensure file permissions prevent unauthorized writes
- File path is fixed in zone file (can't be changed via DNS UPDATE)
- Regular file system security practices apply
- Consider using dedicated directories like `/var/acme/` with appropriate permissions

## Example Complete Setup

**Zone file (`/etc/dnsserver/example.com.zone`):**
```dns
$ORIGIN example.com.
@ 3600 IN SOA ns1.example.com. admin.example.com. 2024012501 3600 1800 604800 86400
@ 3600 IN NS ns1.example.com.
ns1 3600 IN A 192.0.2.1
@ 3600 IN A 192.0.2.100
www 3600 IN A 192.0.2.100

; ACME challenge for main domain
$DYNAMIC _acme-challenge /var/acme/challenge-main.txt

; ACME challenge for wildcard
$DYNAMIC _acme-challenge.www /var/acme/challenge-www.txt
```

**Challenge file management:**
```bash
# Create directory
sudo mkdir -p /var/acme
sudo chown dnsserver:dnsserver /var/acme

# Add challenge (typically done by ACME client)
echo "new-challenge-token" | sudo tee /var/acme/challenge-main.txt

# Test
dig @localhost _acme-challenge.example.com TXT +short

# Clear challenge after validation
sudo rm /var/acme/challenge-main.txt
```

## Troubleshooting

**No TXT records returned:**
- Check file exists and is readable
- Verify file contains non-empty lines
- Check server logs for "Warning: RRDYNAMIC file not found"

**Wrong records returned:**
- File is read on every query - check current file contents
- Remember: duplicates are removed, lines are sorted

**Permission denied:**
- Ensure DNS server process can read the file
- Check directory permissions along the path

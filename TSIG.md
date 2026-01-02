# TSIG (Transaction Signature) Dynamic DNS UPDATE Security

## Overview
This implementation adds RFC 2845 TSIG (Transaction Signature) authentication to DNS UPDATE operations. When a TSIG key is configured for a zone, all UPDATE requests must be cryptographically signed with the matching secret key.

## Supported Algorithms
- HMAC-MD5 (hmac-md5.sig-alg.reg.int.)
- HMAC-SHA1 (hmac-sha1.)
- HMAC-SHA256 (hmac-sha256.) - Recommended
- HMAC-SHA384 (hmac-sha384.)
- HMAC-SHA512 (hmac-sha512.)

## Zone File Configuration

Add a `$TSIG` directive after `$ORIGIN` and before records:

```
$ORIGIN example.com.
$ACL 0.0.0.0/0
$TSIG mykey.example.com. hmac-sha256 K2tf3TRrmE7TJd+m2NPBuw==
example.com. IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400
example.com. IN NS ns1.example.com.
ns1.example.com. IN A 127.0.0.1
```

**Syntax:** `$TSIG keyname algorithm base64_secret`

- `keyname`: FQDN for the key (must match client configuration)
- `algorithm`: One of hmac-md5, hmac-sha1, hmac-sha256, hmac-sha384, hmac-sha512
- `base64_secret`: Base64-encoded shared secret

## Generating TSIG Keys

### Using tsig-keygen (BIND utilities):
```bash
tsig-keygen -a hmac-sha256 mykey.example.com
```

Output:
```
key "mykey.example.com" {
    algorithm hmac-sha256;
    secret "K2tf3TRrmE7TJd+m2NPBuw==";
};
```

### Using ddns-confgen:
```bash
ddns-confgen -a hmac-sha256 -k mykey.example.com
```

### Manual generation (OpenSSL):
```bash
# Generate 32 random bytes and base64 encode
openssl rand -base64 32
```

## Client Configuration

### Using nsupdate:
```bash
# Create key file: mykey.key
cat > mykey.key << EOF
key "mykey.example.com." {
    algorithm hmac-sha256;
    secret "K2tf3TRrmE7TJd+m2NPBuw==";
};
EOF

# Use with nsupdate
nsupdate -k mykey.key << EOF
server 127.0.0.1 5353
zone example.com
update add test.example.com 300 A 10.0.0.1
send
EOF
```

### Using nsupdate (inline):
```bash
nsupdate << EOF
key mykey.example.com. K2tf3TRrmE7TJd+m2NPBuw==
server 127.0.0.1 5353
zone example.com
update add test.example.com 300 A 10.0.0.1
send
EOF
```

## Security Behavior

### With TSIG Configured:
- **Unsigned UPDATE requests are REFUSED**
- Signed UPDATE requests are verified:
  - Key name must match
  - Algorithm must match
  - Timestamp must be within fudge window (default: 300 seconds)
  - MAC (signature) must be valid
- Invalid signatures result in REFUSED response

### Without TSIG Configured:
- UPDATE requests follow ACL-based authorization
- TSIG signatures are ignored (not required)

## Implementation Details

### Files Modified:
- `zone.h` / `zone.cpp` - Added `tsig_key` member to Zone class
- `zoneFileLoader.cpp` - Parse `$TSIG` directive
- `dnsserver.cpp` - TSIG verification in `handleUpdate()`
- `rr.h` / `rr.cpp` - Added TSIG (250) record type

### New Files:
- `rrtsig.h` / `rrtsig.cpp` - TSIG resource record implementation
- `tsig.h` / `tsig.cpp` - TSIG authentication library
- `TSIG.md` - This documentation

### TSIG Verification Process:
1. Extract TSIG record from request (must be last in additional section)
2. Check key name matches zone configuration
3. Check algorithm matches
4. Verify timestamp is within fudge window
5. Compute HMAC over request data + TSIG variables
6. Compare computed MAC with received MAC
7. Allow UPDATE if verification succeeds

### Dependencies:
- OpenSSL library (libssl, libcrypto)
- Used for HMAC computation and Base64 encoding/decoding

## Testing

### Generate Test Key:
```bash
echo "K2tf3TRrmE7TJd+m2NPBuw==" > test_secret.txt
```

### Test Zone File:
```
$ORIGIN test.example.com.
$ACL 0.0.0.0/0
$TSIG testkey.example.com. hmac-sha256 K2tf3TRrmE7TJd+m2NPBuw==
test.example.com. IN SOA ns1.test.example.com. admin.test.example.com. 1 3600 1800 604800 86400
test.example.com. IN NS ns1.test.example.com.
ns1.test.example.com. IN A 127.0.0.1
```

### Test UPDATE with TSIG:
```bash
# With valid TSIG - should succeed
nsupdate << EOF
key testkey.example.com. K2tf3TRrmE7TJd+m2NPBuw==
server 127.0.0.1 5353
zone test.example.com
update add host.test.example.com 300 A 192.168.1.100
send
EOF

# Without TSIG - should be REFUSED
nsupdate << EOF
server 127.0.0.1 5353
zone test.example.com
update add host2.test.example.com 300 A 192.168.1.101
send
EOF
```

## Error Messages

- `TSIG required but not present` - Zone requires TSIG but request has none
- `TSIG present but no key configured` - Request has TSIG but zone doesn't require it
- `TSIG key name mismatch` - Key name doesn't match zone configuration
- `TSIG algorithm mismatch` - Algorithm doesn't match zone configuration
- `TSIG time check failed` - Timestamp outside fudge window
- `TSIG signature verification failed` - MAC verification failed

## Standards Compliance

- RFC 2845: Secret Key Transaction Authentication for DNS (TSIG)
- RFC 2930: Secret Key Establishment for DNS (TKEY) - not implemented
- RFC 4635: HMAC SHA TSIG Algorithm Identifiers

## Limitations

- TSIG signing of responses not implemented (only verification)
- TKEY (dynamic key negotiation) not supported
- GSS-TSIG not supported
- Only supports single TSIG per message
- Fudge time is fixed at 300 seconds

## Backward Compatibility

- Zones without `$TSIG` directive work exactly as before
- ACL-based authorization still applies
- No breaking changes to existing functionality

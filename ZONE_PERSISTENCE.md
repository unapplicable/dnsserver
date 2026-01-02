# Zone Persistence and Auto-Save

## Overview

The DNS server now supports automatic persistence of in-memory zone data back to disk files. This allows dynamic updates (via DNS UPDATE or TSIG-authenticated updates) to be automatically saved, ensuring data survives server restarts.

## Features

1. **Multiple Zone Files** - Load multiple zone files using `-z` parameter
2. **Selective Auto-Save** - Per-zone configuration for persistence
3. **Background Saving** - Automatic save every 5 minutes for modified zones
4. **Atomic Writes** - Backup files (.bak) created before overwriting
5. **SOA Serial Auto-Increment** - Serial automatically incremented on UPDATE
6. **Modification Tracking** - Only save zones that have been modified

## Usage

### Command Line

**New syntax:**
```bash
./dnsserver -z zone1.zone [-z zone2.zone ...] -p 5353 127.0.0.1
```

**Examples:**
```bash
# Single zone file
./dnsserver -z example.com.zone -p 5353 127.0.0.1

# Multiple zone files
./dnsserver -z example.com.zone -z test.com.zone -z internal.zone -p 5353 127.0.0.1

# With other options
./dnsserver -p 5353 -d -z example.zone -z test.zone 192.168.1.1
```

**Note:** The old syntax (zonefile as positional argument) is **no longer supported**. Use `-z` for all zone files.

### Zone File Configuration

Add `$AUTOSAVE` directive to enable persistence:

```
$ORIGIN example.com.
$ACL 0.0.0.0/0
$AUTOSAVE yes
$TSIG updatekey.example.com. hmac-sha256 <secret>

example.com. IN SOA ns1.example.com. admin.example.com. 2026010201 3600 1800 604800 86400
example.com. IN NS ns1.example.com.
ns1.example.com. IN A 192.168.1.1
```

## $AUTOSAVE Directive

**Syntax:** `$AUTOSAVE [yes|no]`

- `$AUTOSAVE` or `$AUTOSAVE yes` - Enable auto-save for this zone
- `$AUTOSAVE no` - Disable auto-save (default)
- Must appear after `$ORIGIN`
- Must appear before zone records

**When to use:**
- **YES:** Dynamic zones updated via DNS UPDATE (e.g., DHCP-managed zones)
- **NO:** Static zones that should not be modified (e.g., master zones)

## How It Works

### 1. Zone Loading
- Server loads all zone files specified with `-z`
- Each zone records its source filename
- `$AUTOSAVE` directive sets the auto-save flag

### 2. Modification Tracking
- When DNS UPDATE adds/removes records, zone is marked as modified
- SOA serial is automatically incremented
- Modification flag persists until zone is saved

### 3. Background Save Thread
- Thread runs every 5 minutes
- Checks all zones for modifications
- Saves zones with `auto_save=true` and `modified=true`
- Atomic save with backup

### 4. File Format
Saved zone files include:
- Header comment with timestamp
- `$ORIGIN` directive
- `$ACL` directive (if configured)
- `$TSIG` directive (if configured)
- SOA record (with incremented serial)
- NS records
- All other records grouped by name

## Safety Features

### Atomic Writes
1. Create backup: `zonefile.bak`
2. Write new file: `zonefile`
3. If write fails, restore from backup
4. Keep `.bak` file for safety

### Thread Safety
- Zone mutex protects all modifications
- Background save acquires mutex before saving
- No race conditions between UPDATE and save

### Error Handling
- Failed saves logged to stderr
- Original file preserved on error
- Backup file kept after successful save

## Example Workflow

### DHCP-DNS Integration

```bash
# 1. Create zone file with AUTOSAVE
cat > dhcp.zone << 'ZONEEOF'
$ORIGIN dhcp.example.com.
$ACL 192.168.1.0/24
$AUTOSAVE yes
$TSIG dhcpkey.example.com. hmac-sha256 <secret>

dhcp.example.com. IN SOA ns1.dhcp.example.com. admin.dhcp.example.com. 1 3600 1800 604800 86400
dhcp.example.com. IN NS ns1.dhcp.example.com.
ns1.dhcp.example.com. IN A 192.168.1.1
ZONEEOF

# 2. Start DNS server
./bin/dnsserver -z dhcp.zone -p 5353 192.168.1.1

# 3. DHCP server sends dynamic updates
# 4. DNS server auto-saves changes every 5 minutes
# 5. Zone file on disk reflects current leases
```

## Log Messages

### Startup
```
[example.com.] Auto-save enabled
[example.com.] Zone file: example.zone
Auto-save thread started (checking every 5 minutes)
```

### During Operation
```
[AUTOSAVE] Zone example.com. has been modified, saving...
Zone example.com.: Successfully saved to example.zone
[AUTOSAVE] Zone example.com. saved successfully
```

or

```
[AUTOSAVE] Zone example.com. save failed!
```

## File Permissions

Ensure the server process has:
- **Read permission** on zone files (for loading)
- **Write permission** on zone file directory (for saving)
- Zone files should be writable by the server process user

## Limitations

1. **Save Interval:** Fixed at 5 minutes (not configurable yet)
2. **No Manual Save:** No signal/command to force immediate save
3. **Format:** Saved files may differ slightly from original (reformatted)
4. **Comments:** Original comments not preserved (except header)
5. **Order:** Records grouped by type for readability

## Migration from Old Syntax

**Old (deprecated):**
```bash
./dnsserver example.zone 127.0.0.1
```

**New (required):**
```bash
./dnsserver -z example.zone 127.0.0.1
```

To migrate scripts, replace:
- Old: `dnsserver zonefile IP`
- New: `dnsserver -z zonefile IP`

## Testing

Test the auto-save feature:

```bash
# 1. Start server with auto-save zone
./bin/dnsserver -z test_autosave.zone -p 15500 127.0.0.1

# 2. Send an UPDATE (in another terminal)
nsupdate -k testkey.conf << EOF
server 127.0.0.1 15500
zone autosave.test
update add testhost.autosave.test 300 A 10.0.0.1
send
EOF

# 3. Wait 5+ minutes or check zone file
# The zone file will be updated with the new record
```

## Future Enhancements

Planned features:
- [ ] Configurable save interval
- [ ] Manual save trigger (SIGUSR1 signal)
- [ ] Save-on-shutdown
- [ ] Preserve original file comments
- [ ] Differential saves (only changed records)
- [ ] Save statistics/metrics

---

**Last Updated:** 2026-01-02  
**Version:** master (zone persistence)

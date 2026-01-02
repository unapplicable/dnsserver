# SIGHUP Zone Reload Feature

## Overview

The DNS server supports runtime zone reloading via the SIGHUP signal. This allows zones to be reloaded from disk without restarting the server, enabling seamless configuration updates.

## How It Works

When the server receives a SIGHUP signal:

1. **Save Modified Zones**: All zones marked with `$AUTOSAVE yes` that have been modified will be saved to their respective files
2. **Clear Existing Zones**: All in-memory zone data is cleared
3. **Reload from Disk**: All zone files are reloaded from disk with fresh data

## Usage

Send SIGHUP to the running DNS server process:

```bash
kill -HUP <pid>
```

Or if you know the process name:

```bash
pkill -HUP dnsserver
```

## Example Workflow

1. Start the server with one or more zone files:
   ```bash
   ./bin/dnsserver -z zone1.zone -z zone2.zone 127.0.0.1
   ```

2. Edit a zone file on disk:
   ```bash
   echo "newhost IN A 10.0.0.100" >> zone1.zone
   ```

3. Send SIGHUP to reload:
   ```bash
   kill -HUP $(pgrep dnsserver)
   ```

4. The server will log the reload process:
   ```
   [SIGHUP] Received reload signal
   [SIGHUP] Saving modified zones...
   [SIGHUP] Clearing existing zones...
   [SIGHUP] Reloading zones from disk...
   [SIGHUP] Reloaded zone file: zone1.zone
   [SIGHUP] Reloaded zone file: zone2.zone
   [SIGHUP] Zone reload complete. Total zones: 2
   ```

## Thread Safety

The SIGHUP handler is thread-safe:
- Uses the global `g_zone_mutex` to synchronize zone modifications
- Prevents race conditions with concurrent DNS queries and updates
- Safe to trigger during active query processing

## Auto-Save Integration

If zones have been modified by dynamic updates and marked with `$AUTOSAVE yes`, they will be automatically saved to disk before reloading. This prevents loss of dynamic updates during reload.

## Implementation Details

- Signal handler sets a volatile atomic flag `g_reload_zones`
- Main server loop checks this flag on each iteration
- Reload is performed synchronously within the main thread
- Uses 1-second timeout on `select()` to enable periodic flag checking
- Available on Linux systems only (requires POSIX signals)

## Error Handling

- If a zone file cannot be opened during reload, an error is logged but other zones continue to load
- If zone file parsing fails, an error is logged and the zone is skipped
- The server continues running even if some zones fail to reload

## Testing

Integration test available: `test_sighup.sh`

```bash
make test-integration
```

## See Also

- [ZONE_PERSISTENCE.md](ZONE_PERSISTENCE.md) - Auto-save and zone persistence
- [MUTATION_TESTING_REPORT.md](MUTATION_TESTING_REPORT.md) - Test coverage

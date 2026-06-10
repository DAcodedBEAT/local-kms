# Local KMS Recovery Tool

CLI for scanning/recovering Local KMS database corruption.

## Overview

Use only when:
- Disk full during DB write
- Corruption detected in DB entries
- Ops fail with "possible data corruption" errors

## Building

From repo root:

```bash
make build-recovery
```

Or manually:

```bash
go build -o recovery ./cmd/recovery
```

## Usage

### Scan for Corruption

```bash
./recovery -db /path/to/kms/data
```

Health check report of corrupted entries.

Example output:
```
Opening database at: /data

=== Running Health Check ===

✓ No corruption detected
```

Or if corruption found:
```
=== Running Health Check ===

⚠ Found issues:

Corrupted Keys:    0
Corrupted Aliases: 1
Corrupted Tags:    0

Details:
  1. corrupted alias at key 'arn:aws:kms:eu-west-2:111122223333:alias/my-key': json: cannot unmarshal...
```

### Remove Corrupted Entries

```bash
./recovery -db /path/to/kms/data -remove-corrupted
```

Tool will:
1. Display all corrupted entries
2. Ask confirmation before removing
3. Remove each corrupted entry
4. Show removal summary

⚠️ **WARNING**: This is destructive and will permanently delete data. Always ensure you have a backup before proceeding.

## Flags

- `-db` - Path to KMS data dir (default: `/data`)
- `-remove-corrupted` - Remove corrupted entries (without flag, scan only)

## Environment Variables

- `KMS_DATA_PATH` - Path to database directory (if `-db` flag is not provided)

## Examples

### Check database health
```bash
./recovery -db /var/lib/local-kms
```

### Backup before recovery
```bash
# Backup the database
cp -r /var/lib/local-kms /var/lib/local-kms.backup

# Run recovery
./recovery -db /var/lib/local-kms -remove-corrupted
```

### Restore from backup if needed
```bash
rm -rf /var/lib/local-kms
cp -r /var/lib/local-kms.backup /var/lib/local-kms
```

## Workflow

1. **Stop KMS service** — no writes during recovery
2. **Back up database** — copy before changes
3. **Scan for corruption** — run without `-remove-corrupted` first
4. **Review report** — understand what's corrupted
5. **Remove corruption** — run with `-remove-corrupted` if safe
6. **Verify recovery** — rescan to confirm clean
7. **Restart service** — bring KMS back online

## See Also

- [RECOVERY_GUIDE.md](../../RECOVERY_GUIDE.md) - Comprehensive recovery procedures
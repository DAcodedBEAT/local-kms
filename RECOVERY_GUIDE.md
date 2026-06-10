# Quick Recovery Guide

"unable to decode ciphertext" or data corruption errors — follow this guide.

## Symptoms

- `WARN[...] Unable to decode Ciphertext: cipher: message authentication failed`
- `ERROR[...] failed to unmarshal key/alias..., possible data corruption`
- Operations failing with `InternalFailureException`
- Disk space low when errors started

## Immediate Steps

### 1. Check Disk Space
```bash
# Check available disk space
df -h

# Recommended: Keep at least 200MB free (LevelDB compaction can temporarily double working set)
# Critical: Keep at least 50MB free (minimum threshold enforced by local-kms)
```

### 2. Identify Corrupted Resources
Check logs for:
- `possible data corruption` messages (note ARN)
- `unable to decode ciphertext` messages (note key ID)
- Timestamp correlation with low disk space

Example log entry:
```
ERROR failed to unmarshal key at arn:aws:kms:eu-west-2:111122223333:key/6865f549-305d-44c3-8aac-ffd2df1845a2, possible data corruption: json: cannot unmarshal ...
```

### 3. Quick Fix Options

#### Option A: Recreate Resources (Recommended)
Corrupted keys:
1. Note key ARN + aliases
2. Delete key (if app doesn't rely on it)
3. Create new key, same specs
4. Update aliases to new key

Corrupted aliases:
1. Note alias ARN
2. Delete: `aws kms delete-alias --alias-name <alias-name>`
3. Create new alias pointing to working key

#### Option B: Stop Using Corrupted Key
If can't recreate immediately:
1. Identify corrupted key/alias
2. Don't use for new operations
3. Create new key/alias for future ops
4. Old encrypted data may be unrecoverable

## Prevention

### 1. Monitor Disk Space
- Alert disk usage > 80%
- Critical alert > 95%
- Cover KMS data directory specifically

### 2. Increase Available Space
```bash
# Identify disk usage
du -sh /path/to/local-kms/data

# Examples for increasing space:
# - Delete unused keys that are pending deletion
# - Archive old backup databases to external storage
# - Increase disk size for the machine
```

### 3. Regular Backups
```bash
# Backup the database directory
cp -r /path/to/local-kms/data /backup/local-kms-backup-$(date +%Y%m%d)

# Keep backups on separate storage
```

## Advanced: Using the Recovery Tool

Recovery utility in repo for advanced corruption scenarios.

### Build the Recovery Tool
```bash
# Build the recovery utility
make build-recovery

# Or manually:
go build -o recovery ./cmd/recovery
```

### Scan for Corruption
```bash
./recovery -db /path/to/kms/data
```

Example output:
```
Opening database at: /path/to/kms/data

=== Running Health Check ===

⚠ Found issues:

Corrupted Keys:    0
Corrupted Aliases: 1
Corrupted Tags:    0

Details:
  1. corrupted alias at key 'arn:aws:kms:eu-west-2:111122223333:alias/my-alias': json: cannot unmarshal...
```

### Remove Corrupted Entries
```bash
# Review what will be removed first
./recovery -db /path/to/kms/data

# Then remove corrupted entries
./recovery -db /path/to/kms/data -remove-corrupted

# Confirm when prompted
Type 'yes' to confirm: yes
```

### Verify Recovery
```bash
# Run health check again to confirm corruption is gone
./recovery -db /path/to/kms/data
```

Should output:
```
✓ No corruption detected
```

## Getting Help

Check [GitHub Issues](https://github.com/nsmithuk/local-kms/issues) or file bug with local-kms version, log snippets, disk space at failure time.

## Related Documentation

- See [README.md](README.md) for general usage
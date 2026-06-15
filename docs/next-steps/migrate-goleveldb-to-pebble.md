# Migrate persistence: goleveldb → Pebble

## Motivation

`github.com/syndtr/goleveldb` is effectively unmaintained:

- Last tag `v1.0.0` (2019). Current pin is an Aug 2021 master pseudo-version.
- Drags stale transitive deps into the module graph (`gopkg.in/yaml.v2`, old `golang.org/x/net`, old `golang.org/x/crypto`, old `ginkgo`/`gomega`).
- No security backports, no fixes for newer Go runtimes.

`github.com/cockroachdb/pebble` is the natural replacement:

- Actively maintained, production engine for CockroachDB.
- LSM KV, same access patterns we use (Get/Put/Delete + prefix iteration).
- Clean module graph, current Go support.

## Scope

Replace goleveldb across the persistence layer. Preserve existing on-disk data via one-shot in-place migration on first open.

## Follow-on cleanup (do alongside migration)

Once Pebble ships, retire the recovery utility — its only purpose is repairing goleveldb corruption under disk pressure, irrelevant on Pebble (manifest replay + WAL).

- Delete `cmd/recovery/`, `RECOVERY_GUIDE.md`, `make build-recovery`.
- Drop `recovery_*` artifacts from `.github/workflows/ci.yml` (`binaries` matrix build step + release files glob).
- Remove the transitional-tool callout from `README.md` download section.

## Affected files

| File | Change |
|------|--------|
| `go.mod` / `go.sum` | drop `syndtr/goleveldb`, add `cockroachdb/pebble` |
| `src/data/database.go` | swap engine, add migration entry point |
| `src/data/database_key.go` | iterator + `ErrNotFound` |
| `src/data/database_alias.go` | iterator |
| `src/data/database_tag.go` | iterator |
| `src/seed.go` | `ErrNotFound` references |
| `src/data/migrate_leveldb.go` (new) | one-shot migration helper |

API surface in use is small. Audited via grep:

- `leveldb.OpenFile` / `leveldb.RecoverFile`
- `db.Get`, `db.Put(sync)`, `db.Delete(sync)`
- `db.NewIterator(util.BytesPrefix(p), nil)` + `iter.Next/Key/Value/Release/Error`
- `leveldb.ErrNotFound`

All map cleanly to Pebble.

## On-disk compatibility

Pebble is **not** a drop-in reader for goleveldb data directories.

- goleveldb writes LevelDB format: `CURRENT`, `MANIFEST-*`, `LOG`, `*.ldb`.
- Pebble derives from RocksDB conventions: own manifest, WAL, sstable variant, `OPTIONS-*` file, `marker.*` files.
- Pebble reads RocksDB sstables, not LevelDB stores. CockroachDB docs are explicit: no LevelDB drop-in.

Conclusion: cannot reuse the directory in place. Must migrate KV contents into a fresh Pebble directory. Migration is cheap — KMS keyspace per consumer is tiny (keys + aliases + tags per ARN, full scan in milliseconds).

## Migration design

One-shot, idempotent, runs inside `NewDatabase(ctx, path)`. No separate CLI step. Consumers upgrade and restart.

### Detection

At `path`, classify directory:

- **Pebble**: `marker.format-version.*` or `OPTIONS-*` present → open directly.
- **goleveldb**: `CURRENT` + `MANIFEST-*` present, no Pebble markers → migrate.
- **empty / nonexistent**: open fresh Pebble.
- **ambiguous**: refuse to start, log error with both signals listed.

### Migration steps

1. Acquire OS file lock at `path/.migrate.lock` (refuse if held — prevents concurrent migration).
2. Open existing dir with goleveldb in read-only mode.
3. Create sibling dir `path + ".pebble.tmp"`. Open with Pebble.
4. Iterate full keyspace from goleveldb. Stream into a Pebble `Batch`. Commit batch with `pebble.Sync` every N entries (e.g. 1000) and at end.
5. Close both engines.
6. Atomic swap:
   - Rename `path` → `path + ".leveldb.bak.<timestamp>"`.
   - Rename `path + ".pebble.tmp"` → `path`.
7. Release lock. Open `path` with Pebble for normal use. Log migration summary (entry count, elapsed).

Failure handling: if any step fails before the rename, delete `.pebble.tmp`, leave original untouched, return error and let process exit. If failure occurs mid-rename, log clear instructions for manual recovery (both dirs still present on disk).

### Rollback

Keep `*.leveldb.bak.*` for one release cycle. Document removal in release notes. Provide a `--purge-leveldb-backup` flag (or doc the manual `rm`) for the release that drops the backup.

## Code changes

### `database.go`

```go
type Database struct {
    database *pebble.DB
    dbPath   string
}

var syncWrite = pebble.Sync

func NewDatabase(ctx context.Context, path string) *Database {
    kind, err := classifyDir(path)
    if err != nil {
        panic(err)
    }
    if kind == dirLevelDB {
        if err := migrateLevelDBToPebble(ctx, path); err != nil {
            panic(err)
        }
    }
    db, err := pebble.Open(path, &pebble.Options{})
    if err != nil {
        panic(err)
    }
    return &Database{database: db, dbPath: path}
}
```

Drop the `RecoverFile` branch — Pebble auto-replays WAL on open.

### Put/Delete

```go
func (d *Database) put(key, value []byte) error {
    if err := CheckDiskSpace(d.dbPath); err != nil {
        return err
    }
    return d.database.Set(key, value, syncWrite)
}

func (d *Database) DeleteObject(arn string) error {
    if err := CheckDiskSpace(d.dbPath); err != nil {
        return err
    }
    return d.database.Delete([]byte(arn), syncWrite)
}
```

### Get

```go
val, closer, err := d.database.Get(key)
if errors.Is(err, pebble.ErrNotFound) { ... }
defer closer.Close()
```

Note: Pebble `Get` returns a `closer` that must be released. Wrap in a small helper to keep call sites readable.

### Prefix iteration

Pebble has no `util.BytesPrefix`. Add helper:

```go
func prefixRange(prefix []byte) *pebble.IterOptions {
    return &pebble.IterOptions{
        LowerBound: prefix,
        UpperBound: prefixSuccessor(prefix),
    }
}

func prefixSuccessor(p []byte) []byte {
    end := make([]byte, len(p))
    copy(end, p)
    for i := len(end) - 1; i >= 0; i-- {
        end[i]++
        if end[i] != 0 {
            return end[:i+1]
        }
    }
    return nil // unbounded
}
```

Iterator usage:

```go
iter, _ := d.database.NewIter(prefixRange([]byte(prefix)))
defer iter.Close()
for iter.First(); iter.Valid(); iter.Next() {
    k := iter.Key()
    v := iter.Value()
    ...
}
if err := iter.Error(); err != nil { ... }
```

### `ErrNotFound` references

`src/data/database_key.go:73` returns `leveldb.ErrNotFound` to callers. `src/seed.go:141,157` compare against it. Centralize:

```go
// src/data/errors.go
var ErrNotFound = pebble.ErrNotFound
```

Update both call sites to use `data.ErrNotFound`. Keeps engine leak out of `seed.go`.

## Testing

- Unit: migration helper with synthetic goleveldb dir (created in test setup using goleveldb still in `go.mod` as a test-only dep, or pre-built fixture committed under `testdata/`). Assert post-migration Pebble dir contains identical KV set.
- Unit: `prefixSuccessor` edge cases — empty, all `0xFF`, single byte.
- Integration: existing handler tests must pass unchanged against fresh Pebble store.
- Manual: spin up against a real local-kms data dir from a previous release, restart, confirm keys/aliases/tags readable and AWS SDK round-trips succeed.

## Risks

- **Sync semantics**: goleveldb `Sync: true` ≈ Pebble `pebble.Sync`. Both fsync WAL before returning. Equivalent durability.
- **Performance**: Pebble is faster on writes, comparable on reads. Not a concern at local-kms scale.
- **Disk usage during migration**: temporarily doubles. Acceptable for KMS-sized data. Document in release notes.
- **Cross-platform**: Pebble supports linux/darwin/windows. Same as goleveldb.
- **CGO**: Pebble is pure Go. No cgo introduced.

## Out of scope

- Configurable backends. One engine, one format.
- Online migration (process keeps serving). Restart-based migration is sufficient.
- Removing the `*.leveldb.bak.*` cleanup logic — defer to follow-up release.

## Rollout

1. Land migration PR. Default behavior: migrate on first boot, keep backup.
2. Release notes: highlight migration, backup location, how to roll back (stop process, swap dirs).
3. One release later: add `--purge-leveldb-backup` flag, document removal.
4. Two releases later: drop migration code path entirely; classify-as-LevelDB now errors with "run vX.Y once to migrate".

## Checklist

- [ ] Add `cockroachdb/pebble` to `go.mod`
- [ ] `src/data/database.go` swap to Pebble
- [ ] `src/data/migrate_leveldb.go` new
- [ ] `src/data/errors.go` new (`ErrNotFound`)
- [ ] Rewrite iterators in `database_key.go`, `database_alias.go`, `database_tag.go`
- [ ] Update `seed.go` to use `data.ErrNotFound`
- [ ] Migration unit tests + fixture
- [ ] Drop `syndtr/goleveldb` from `require` (keep in test-only deps if fixture uses it, else remove)
- [ ] `go mod tidy`, confirm `yaml.v2` and stale `x/net` drop out
- [ ] Release notes

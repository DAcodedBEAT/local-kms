# Add Go unit tests

## Context

Repo currently has **zero** `*_test.go` files. All test coverage comes from the Python functional suite in `tests/functional/` — pytest hitting a running container over HTTP. That is end-to-end coverage, not unit coverage.

Result:
- A bug in pure logic (key encoding, ARN parsing, blob layout, policy validation) only surfaces if a functional test happens to exercise the surrounding HTTP shape.
- Refactors are scary — no fast feedback loop, no way to assert behavior at the function level.
- The functional suite is slow (container spin-up + pytest run) so devs don't run it on every change.

## Goal

Establish a baseline of Go unit tests so that core logic has fast, in-process coverage. Functional tests stay; unit tests fill the gap underneath.

## Where to start (high-value targets)

Pure-function modules first — biggest signal-to-noise:

1. **`src/cmk/`** — key construction, AES/RSA/ECC primitives, hash, errors. Almost no I/O. Ideal first batch.
2. **`src/service/`** — ARN parsing, key/alias lookup, policy validation. Some leveldb dep — use temp dir + real DB or interface seam.
3. **`src/handler/helpers.go`** + request shape parsing — easy table-driven tests.
4. **Ciphertext blob format** (`[1B ARN len][ARN][4B version LE][12B nonce][AES-GCM]`) — golden-file tests so format never silently drifts. README documents the layout; lock it in code.
5. **Seeding** (`src/seed.go`) — yaml fixtures → expected key state.

Lower priority (more I/O setup needed):
- `src/handler/*.go` HTTP endpoints — better covered by existing functional suite.
- `src/data/` leveldb wrapper — thin layer over an external library.

## Conventions to adopt

- Table-driven tests (`tt := []struct{name string; …}{…}`) — Go idiom.
- `t.TempDir()` for any filesystem state. No global `/tmp` paths.
- Avoid mocking what's cheap to construct (real AES key, real leveldb in temp dir).
- Race detector in CI: `go test -race ./...`.
- Coverage threshold: don't set a hard gate on day one. Track coverage % over time; raise the bar gradually.

## CI wiring

Add a `unit` job to `.github/workflows/ci.yml`:

```yaml
unit:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-go@v5
      with:
        go-version-file: go.mod
        cache: true
    - run: go test -race -count=1 -coverprofile=coverage.out ./...
    - uses: actions/upload-artifact@v4
      with:
        name: coverage
        path: coverage.out
```

Should run on every PR. Fast (< 30s once tests exist).

## Out of scope

- Replacing the functional suite. Keep it.
- Coverage gates. Add later once baseline exists.
- Property-based testing — nice-to-have for crypto blob round-trips, defer.

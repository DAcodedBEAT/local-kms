# Migrate `src/x509/` + `src/cmk/ecc_key.go` to `crypto/ecdh`

## Context

`.golangci.yml` excludes `staticcheck:SA1019` for `src/x509/*.go` and `src/cmk/ecc_key.go`. The rest of the lint set (`errcheck`, `govet`, `ineffassign`, `unused`, `misspell`, `staticcheck`, `gosec`) runs clean across the rest of the tree.

Excluded sites use Go 1.21–1.26 deprecated APIs. They were carried over from upstream and need a focused refactor:

- `src/x509/sec1.go:34` — `key.D.FillBytes(privateKey)` — direct access to `ecdsa.PrivateKey.D` deprecated since Go 1.26. Use `MarshalPKCS8PrivateKey` or `crypto/ecdh.PrivateKey.Bytes`.
- `src/x509/sec1.go:36` — `elliptic.Marshal(key.Curve, key.X, key.Y)` — deprecated since Go 1.21. Use `crypto/ecdh.PublicKey.Bytes`.
- `src/x509/x509.go:152` — same `elliptic.Marshal`. Same migration.
- `src/x509/pkcs1.go:124-125` — reads `key.Precomputed.CRTValues`. Deprecated since Go 1.21; values still populated for backwards compat but unused by Go's RSA implementation. Path forward: stop emitting `AdditionalPrimes` (multi-prime RSA in PKCS#1 v2 is rare and unused by AWS KMS anyway), or compute CRT values manually if needed.
- `src/cmk/ecc_key.go:220` — `pk.D = marshaledKey.D` writes through the deprecated big.Int field. Switch to `crypto/x509.ParsePKCS8PrivateKey` / `crypto/x509.MarshalPKCS8PrivateKey`, or `crypto/ecdh` for ECDH-only consumers.

## Why this is its own PR

Touches ASN.1 PEM round-trip. Consumers of seed-file-generated keys (and any persisted key material) depend on byte-for-byte output stability. Migration needs:

1. Read existing PEM/DER blobs with new APIs.
2. Confirm output bytes match the previous output for the same input (golden-file test).
3. Run the functional test suite end-to-end (encrypt/decrypt, sign/verify, get-public-key) to catch behavioural drift.

Bundling that with infra cleanup would muddy the review.

## After migration

Remove the `staticcheck:SA1019` exclusions from `.golangci.yml`:

```yaml
linters:
  exclusions:
    rules: []   # drop the src/x509 + ecc_key entries
```

CI workflow needs no change.

## Already done (don't redo)

The following findings were addressed alongside this doc and do not need a second pass:

- `put_key_policy.go` unchecked decode err — fixed (`src/handler/put_key_policy.go`).
- `create_alias.go` `fmt.Sprintf` w/o verbs — fixed.
- `server.go` `http.ListenAndServe` no timeouts — replaced with `&http.Server{ReadHeaderTimeout, ReadTimeout, WriteTimeout, IdleTimeout}`.
- AES blob ARN length bound — `len(identBytes) > 255` guard added.
- gosec G115 conversions in `aes_encryption.go` + `generate_data_key.go` — annotated with `#nosec` + justification.
- `crypto/sha1` import for OAEP-SHA1 wrapping — annotated.
- `seed.go` operator-controlled path — annotated.
- `create_key.go` deprecated `CustomerMasterKeySpec` field — annotated (must remain for AWS-spec input compat).
- `import_key_material.go` `rsa.PKCS1v15DecryptOptions` — annotated (mandated by AWS wrapping algorithm).
- `server.go` 501-response taint flag — annotated.

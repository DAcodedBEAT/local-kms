# Changelog

## [3.13.0](https://github.com/DAcodedBEAT/local-kms/compare/v3.12.0...v3.13.0) (2026-08-26)


### Features

* add grants API support ([6b2ab15](https://github.com/DAcodedBEAT/local-kms/commit/6b2ab15a3eb38feafc8bc05407673fa4b4a777a1))
* add RotateKeyOnDemand support ([43b9935](https://github.com/DAcodedBEAT/local-kms/commit/43b99352603c9617c2b944c5b2e263d8f5eef1d4))

## [3.12.0](https://github.com/DAcodedBEAT/local-kms/compare/v3.11.7...v3.12.0) (2026-07-23)


### Features

* add HMAC key support (HMAC_224/256/384/512) ([55bb74a](https://github.com/DAcodedBEAT/local-kms/commit/55bb74a61000ee1cffcbdd562e0bb5265f7193b7))
* modernize stack, align to AWS KMS spec, expand test coverage ([e48f420](https://github.com/DAcodedBEAT/local-kms/commit/e48f420d88cea44f1f73cd201a6810f33d3d834a))
* **server:** bind before announcing, resolve PORT=0 in logs ([e341217](https://github.com/DAcodedBEAT/local-kms/commit/e3412170330f902683997bfa89f02c88ce0cb844))


### Bug Fixes

* HMAC/AES pending-import metadata, key-import type safety, uuid errors ([6772a7a](https://github.com/DAcodedBEAT/local-kms/commit/6772a7aa1cb9c8fed50616a3491f384e7e2eb39c))


### Refactors

* migrate to slog and consolidate core logic ([b604fa3](https://github.com/DAcodedBEAT/local-kms/commit/b604fa326805bff87a362e4cf93bc0c151afa707))

# Use docker-compose.test.yml in CI functional tests

## Context

`.github/workflows/ci.yml` (`docker` job) currently runs functional tests with manual `docker run` calls: builds the kms image with `load: true`, creates a docker network, starts the container, polls `/_health` via a `curlimages/curl` container, then runs the test image against it.

`docker-compose.test.yml` already encodes the same setup declaratively: a `kms` service with a `healthcheck` on `/_health`, and a `test` service with `depends_on: { kms: { condition: service_healthy } }` that runs pytest. It's what local dev uses.

CI reinvents what compose already does. Drift risk: local-passing tests, CI-failing (or vice versa).

## Goal

Replace the manual `docker run` / network / health-loop block in the `docker` job with a single `docker compose` invocation against `docker-compose.test.yml`. CI and local use the same orchestration.

## Approach

Two options:

**A. Override the kms build to reuse the buildx-loaded image.**
- Build amd64 image with `load: true` tagged `local-kms:test` (already happens).
- Add `docker-compose.test.ci.yml` override that replaces `build:` with `image: local-kms:test` for the kms service.
- Run: `docker compose -f docker-compose.test.yml -f docker-compose.test.ci.yml run --rm test`
- Pros: reuses cached buildx image, no double-build.
- Cons: extra compose file to maintain.

**B. Let compose build the kms image itself.**
- Drop the separate buildx `load: true` step.
- Run: `docker compose -f docker-compose.test.yml run --build --rm test`
- Pros: single source of truth, no override file.
- Cons: compose's `docker build` doesn't share GHA buildx cache by default — slower cold builds. Possible workarounds: `COMPOSE_BAKE=true` + buildx bake, or pre-warm cache with a separate buildx step that exports to the local docker daemon.

Recommend **A** for cache reuse, unless cold build time turns out negligible.

## Steps

1. Decide between A and B (try A first).
2. If A: add `docker-compose.test.ci.yml` with `services.kms.image: local-kms:test` and remove `build:`.
3. Update `.github/workflows/ci.yml` `Functional tests` step to invoke compose instead of raw docker.
4. Verify: tests pass, exit code propagates correctly (compose `run` returns the command's exit code; OK).
5. Confirm logs are still useful on failure — may want `docker compose logs kms` on test failure.
6. Remove the now-dead manual network/health-loop block.

## Out of scope

- Switching the multi-arch push step (still needs raw buildx for `linux/amd64,linux/arm64`).
- Changing test framework or test image.

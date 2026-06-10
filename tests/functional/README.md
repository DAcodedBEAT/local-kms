# Local KMS Functional Tests

There are two goals to these tests:
* Regression testing for Local KMS.
* Generating a set of tests that can be run against AWS KMS and Local KMS, to ensure the two match.

#### Why are they in Python?
There are a few reasons:
* It allows different encryption libraries to be used from those that generate keys in Local KMS. The demonstration that
generated keys are compatible with other libraries adds weight to the fact they're initially being generated correctly.
* Python's Duck typing allows us to spend less time thinking about all the data structures being passed around, so we can focus
on just the element we're currently testing.
* It's quite quick and easy.

## Quick Start (Recommended)

Run all tests in Docker with one command from the repository root:

```bash
./run-tests.sh
```

Or using Make:
```bash
make test
```

That's it! No Python setup needed - everything runs in Docker containers.

## Alternative Setup Methods

### Option 1: Docker Compose (Full Control)

From the repository root:
```bash
docker-compose -f docker-compose.test.yml up --build
```

### Option 2: Native Python (Manual)

From within the `tests/functional` directory:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirments.txt

# Start KMS in another terminal
cd ../..
docker-compose up

# Back in tests/functional, run tests
export KMS_URL=http://localhost:4599
pytest
```

### Option 3: Docker Python Container (Linux Recommended)

secg_p256k1 is not well supported on Mac OS X, so it's recommended you run the tests from within a Linux Docker container.

From within `tests/functional`:
```bash
docker run -it --rm -v "${PWD}:/app" -w "/app" \
-e AWS_ACCESS_KEY_ID \
-e AWS_SECRET_ACCESS_KEY \
-e AWS_SESSION_TOKEN \
python:3-slim bash

pip install -r requirments.txt
export KMS_URL="http://host.docker.internal:4599"
pytest
```

## Running Specific Tests

Run a single test file:
```bash
docker-compose -f docker-compose.test.yml exec test pytest -v tests/cmk/test_error_handling.py
```

Run a specific test:
```bash
docker-compose -f docker-compose.test.yml exec test pytest -v tests/cmk/test_error_handling.py::TestAliasErrorHandling::test_encrypt_decrypt_with_alias_after_operations
```

## Test Categories

### Core Tests
- `tests/cmk/test_key_management.py` - Key creation, deletion, scheduling, etc.
- `tests/cmk/test_aliases.py` - Alias operations
- `tests/aes/test_generate_data_key_pair.py` - AES key generation
- `tests/sign/test_signing.py` - Signing operations

### New: Error Handling & Corruption Prevention
- `tests/cmk/test_error_handling.py` - Error propagation, alias lifecycle, data integrity
  - Tests the exact scenario that caused corruption when disk space was low
  - Verifies alias delete/recreate cycles work correctly
  - Validates tag operations maintain data integrity

## Cleanup

Stop test containers:
```bash
make test-down
```

Or manually:
```bash
docker-compose -f docker-compose.test.yml down
```

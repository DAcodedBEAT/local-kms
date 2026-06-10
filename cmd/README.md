# Entrypoints

Executable entrypoints for Local KMS project.

## Structure

```
cmd/
├── local-kms/        Main KMS service
│   └── main.go       KMS server entrypoint
└── recovery/         Database recovery utility
    ├── main.go       Recovery tool entrypoint
    └── README.md     Recovery tool documentation
```

## Building

### Build all binaries
```bash
make build       # Build local-kms
make build-recovery  # Build recovery tool
```

### Build individual binaries
```bash
go build -o local-kms ./cmd/local-kms
go build -o recovery ./cmd/recovery
```

## Running

### Local KMS Server
```bash
./local-kms
```

Env vars:
- `KMS_ACCOUNT_ID` - AWS account ID (default: 111122223333)
- `KMS_REGION` - AWS region (default: eu-west-2)
- `KMS_DATA_PATH` - Path to database directory (default: /tmp/local-kms)
- `KMS_SEED_PATH` - Path to seed file (default: /init/seed.yaml)
- `PORT` - HTTP port (default: 8080)

### Recovery Tool
```bash
./recovery -db /path/to/data              # Scan for corruption
./recovery -db /path/to/data -remove-corrupted  # Fix corruption
```
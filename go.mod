module github.com/nsmithuk/local-kms

go 1.26

require (
	github.com/aws/aws-sdk-go-v2/service/kms v1.53.4
	github.com/btcsuite/btcd/btcec/v2 v2.5.0
	github.com/google/uuid v1.6.0
	github.com/syndtr/goleveldb v1.0.1-0.20210819022825-2ae1ddf74ef7
	go.yaml.in/yaml/v4 v4.0.0-rc.5
	golang.org/x/sys v0.46.0
)

require (
	github.com/aws/aws-sdk-go-v2 v1.42.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.29 // indirect
	github.com/aws/smithy-go v1.27.2 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/onsi/gomega v1.39.1 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/telemetry v0.0.0-20260610154732-fb80ec83bdd9 // indirect
	golang.org/x/text v0.38.0 // indirect
	golang.org/x/tools v0.46.0 // indirect
	golang.org/x/vuln v1.3.0 // indirect
)

tool (
	golang.org/x/tools/cmd/goimports
	golang.org/x/vuln/cmd/govulncheck
)

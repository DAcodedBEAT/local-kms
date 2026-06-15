# Local KMS (LKMS)

Mock AWS Key Management Service for local dev/testing. Written in Go.

_Uses real encryption ([AES](https://golang.org/pkg/crypto/aes/), [ECDSA](https://golang.org/pkg/crypto/ecdsa/), [RSA](https://golang.org/pkg/crypto/rsa/)), but designed for dev/test against KMS — not production._

#### (Local) KMS Usage Guides
* [Using AWS KMS via the CLI with a Symmetric Key](https://nsmith.net/aws-kms-cli)
* [Using AWS KMS via the CLI with Elliptic Curve (ECC) Keys](https://nsmith.net/aws-kms-cli-ecc)
* [Using AWS KMS via the CLI with RSA Keys for Message Signing](https://nsmith.net/aws-kms-cli-rsa-signing)

## Features

### Supports

* Symmetric (AES) keys
* HMAC keys (`HMAC_224`, `HMAC_256`, `HMAC_384`, `HMAC_512`)
* Asymmetric keys (ECC and RSA)
* Customer Master Key management:
    * Enable/disable keys
    * Schedule key deletion
    * Enable/disable automated key rotation
* Key alias management
* Encryption
    * Encryption Contexts
* Decryption
* Data key generation, with or without plain text
* Data key pair generation, with or without plain text
* Random data generation
* Custom key material import
* Sign/verify messages
    * RAW and DIGEST
* MAC generation and verification (`GenerateMac`, `VerifyMac`) using HMAC keys
* Tags
* Key Policies: Get & Put

#### Seeding
Seeding supplies pre-defined keys and aliases on startup — deterministic, versionable test key management.

Existing keys in seeding file not overwritten or amended.

### Does not (yet) support

* Grants (`CreateGrant`, `ListGrants`, `RevokeGrant`, `RetireGrant`, `ListRetirableGrants`)
* On-demand key rotation (`RotateKeyOnDemand`, `ListKeyRotations`)
* Multi-region keys (`MultiRegion: true`, `mrk-` key ID prefix, `ReplicateKey`, `UpdatePrimaryRegion`)
* `ListKeyPolicies`
* `DeriveSharedSecret` (ECDH shared secret derivation)
* Custom Key Store operations

### Differences from AWS KMS

#### Ciphertext format

Local KMS uses custom binary format **not compatible with real AWS KMS** or moto (Python AWS mock library). Ciphertext produced by Local KMS cannot be decrypted by moto or real KMS, and vice versa. Format embeds full key ARN and backing-key version index for correct key rotation:

```
[1 byte: ARN length][ARN bytes][4 bytes: key version (LE uint32)][12-byte nonce][AES-GCM ciphertext+tag]
```

Don't mix environments (local-kms ↔ moto ↔ real KMS) for same encrypted data.

#### Key rotation

Local KMS implements real key rotation: when enabled, new backing key appended to `BackingKeys` array each rotation cycle (annually by default). New encryptions use newest backing key; existing ciphertext still decrypts via version index in blob.

AWS KMS and moto track rotation state but cryptographic rotation behavior differs in implementation. Tests relying on rotation-specific ciphertext versioning only pass against Local KMS.

#### `ScheduleKeyDeletion` timestamp format

AWS returns deletion timestamp in scientific notation (e.g. `1.5565824E9`). Local KMS returns plain integer (`1556582400`). Official AWS SDKs treat these identically.

## Download

Pre-built binaries from [GitHub Releases](https://github.com/DAcodedBEAT/local-kms/releases/latest). Static (CGO disabled) — Linux binaries run on glibc and musl/Alpine alike:

* `local-kms_darwin-amd64.bin` / `recovery_darwin-amd64.bin`
* `local-kms_darwin-arm64.bin` / `recovery_darwin-arm64.bin`
* `local-kms_linux-amd64.bin`  / `recovery_linux-amd64.bin`
* `local-kms_linux-arm64.bin`  / `recovery_linux-arm64.bin`

> `recovery_*` is a transitional utility for repairing goleveldb corruption. Slated for removal once the datastore migration to Pebble lands (see [`docs/next-steps/migrate-goleveldb-to-pebble.md`](docs/next-steps/migrate-goleveldb-to-pebble.md)).

Direct download (latest):
```sh
curl -L -o local-kms \
  https://github.com/DAcodedBEAT/local-kms/releases/latest/download/local-kms_linux-amd64.bin
chmod +x local-kms
```

## Getting Started with Docker

Images published to [GitHub Container Registry](https://github.com/DAcodedBEAT/local-kms/pkgs/container/local-kms): `ghcr.io/dacodedbeat/local-kms`. Multi-arch (amd64, arm64).

Tags:
- `latest` — tip of `master`
- `X.Y.Z` — specific semver release
- `X` — latest within major version
- `sha-<short>` — exact commit

Quickest start — LKMS up on port 8080:
```
docker run -p 8080:8080 ghcr.io/dacodedbeat/local-kms
```

### Seeding and Docker
LKMS checks for seeding file at `/init/seed.yaml` by default. Simplest approach: mount host directory containing `seed.yaml`.

```
docker run -p 8080:8080 \
--mount type=bind,source="$(pwd)"/init,target=/init \
ghcr.io/dacodedbeat/local-kms
```

### Persisting data and Docker
Docker stores data in `/data/` by default. To persist between runs, mount `/data` to host filesystem.
```
docker run -p 8080:8080 \
--mount type=bind,source="$(pwd)"/data,target=/data \
ghcr.io/dacodedbeat/local-kms
```

## Seeding file format

_Symmetric and Asymmetric (RSA and ECC) keys supported in seeding file._

Simple seeding file:
```yaml
Keys:
  Symmetric:
    Aes:
      - Metadata:
          KeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
        BackingKeys:
          - 5cdaead27fe7da2de47945d73cd6d79e36494e73802f3cd3869f1d2cb0b5d7a9
  Asymmetric:
    Ecc:
      - Metadata:
          KeyId: 800d5768-3fd7-4edd-a4b8-4c81c3e4c147
          KeyUsage: SIGN_VERIFY
          Description: ECC key with curve secp256r1
        PrivateKeyPem: |
          -----BEGIN EC PRIVATE KEY-----
          MHcCAQEEIMnOrUrXr8rwne7d8f01cfwmpS/w+K7jcyWmmeLDgWKaoAoGCCqGSM49
          AwEHoUQDQgAEYNMBBZ3h1ipuph1iO5k+yLvTs94UN71quXN3f0P/tprs2Fp2FEas
          M7m7XZ2xlDK3wcEAs1QEIoQjjwnhcptQ6A==
          -----END EC PRIVATE KEY-----

Aliases:
  - AliasName: alias/testing
    TargetKeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
```
Creates two keys: AES key with ID `bc436485-5092-42b8-92a3-0aa8b93536dc` and 256-bit ECC key. Alias `alias/testing` points to AES key.

`BackingKeys` must be array of **one or more** hex-encoded 256-bit keys (generate with `openssl rand -hex 32`). Only AES keys support backing keys.

Seeding files support multiple keys, aliases, and backing keys. Multiple backing keys simulates CMK rotation.

```yaml
Keys:
  Symmetric:
    Aes:
      - Metadata:
          KeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
        BackingKeys:
          - 34743777217A25432A46294A404E635266556A586E3272357538782F413F4428
          - 614E645267556B58703273357638792F423F4528472B4B6250655368566D5971
      
      - Metadata:
          KeyId: 49c5492b-b1bc-42a8-9a5c-b2015e810c1c
        BackingKeys:
          - 5cdaead27fe7da2de47945d73cd6d79e36494e73802f3cd3869f1d2cb0b5d7a9


Aliases:
  - AliasName: alias/dev
    TargetKeyId: bc436485-5092-42b8-92a3-0aa8b93536dc

  - AliasName: alias/test
    TargetKeyId: 49c5492b-b1bc-42a8-9a5c-b2015e810c1c

```

Optional key fields:
- **Metadata -> Description**: Free text key description.
- **Metadata -> Origin**: Set to `EXTERNAL` for custom key material. With `EXTERNAL`, `BackingKeys` is optional array of at most 1 hex-encoded 256-bit key.
- **Metadata -> KeyUsage**: Asymmetric keys only. ECC supports `SIGN_VERIFY` only. RSA supports `SIGN_VERIFY` or `ENCRYPT_DECRYPT`.
- **NextKeyRotation**: AES keys only. ISO 8601 date. Enables rotation, sets next rotation date. Past date triggers rotation on first key access.

```yaml
Keys:
  Symmetric:
    Aes:
      - Metadata:
          KeyId: bc436485-5092-42b8-92a3-0aa8b93536dc
          Description: "Your key description"
        NextKeyRotation: "2019-09-12T15:19:21+00:00"
        BackingKeys:
          - 34743777217A25432A46294A404E635266556A586E3272357538782F413F4428
      - Metadata:
          KeyId: 5ef77041-d1e6-4af1-9a41-e49a4b45efb6
          Origin: EXTERNAL
        BackingKeys:
          - b200b324de29609558e13780160e38fc193f6bec9f9dba58a2be5b37d5098d74
      - Metadata:
          KeyId: 5d05267f-bb87-4d0b-8594-295a4371d414
          Origin: EXTERNAL
```
Above creates 2 `EXTERNAL` origin keys:
- `5ef77041-d1e6-4af1-9a41-e49a4b45efb6` with pre-imported key material
- `5d05267f-bb87-4d0b-8594-295a4371d414` in `PendingImport` state


```yaml
Keys:
  Asymmetric:
    Rsa:
      - Metadata:
          KeyId: ff275b92-0def-4dfc-b0f6-87c96b26c6c7
          KeyUsage: SIGN_VERIFY # or ENCRYPT_DECRYPT
          Description: RSA key with 2048 bits
        PrivateKeyPem: |
          -----BEGIN PRIVATE KEY-----
          MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQD21epc1564DeWZ
          80XYAXTo4tjqJzEQ6VdpkRfKHraJ4WNqS8N5HjfyzmADVOgqqlbm5M+Qq0/ViMd/
          Xqh+OUNhwvEIo6iZuNbWba3/cUV9ZFpmCv9IWvlNojc3zq0C9/fXeSqXwZWut78d
          AuFodRdAnENiHf9aXv4pIyszAxALCSCd/UCYZRw+XUDPG4pSJrwgz2Ohkqr1SnFF
          1aQt6onjt3Rtfn5IUs7BGEXGd6M3HeIlikSLjdoXEuevVaZO0ysiQdiYDYYQ2eFe
          ytXefRuotRqH4dLpL6beUFRbT1MQVtqC2S0K2wWq8T5gTFejxv6E6eVqRC2xu0lj
          TGDxnUC3AgMBAAECggEAU6K73GV69CZRS86wNbaYpGho0z4gU/ick7qD8wphE2r5
          QoUVYK6qimz+/2H/oKVC+M1Cv2Qsks/buP6b3NkOScvB3AmIET4eHV3gfRMmVoxw
          TO8g/KVGn9V9HD29Rao7ohj+I5mGXEMKUIwvUDOMg2nvMwmzAi35tHqkIo7BGtt8
          gBuuHsZj9PM6MYSSZdrHP52T3K15MaHfrLb97UaryyYnhnUmBA12DBE8MseuYA7w
          JwL3os6MwtLxRxgXnBhkk3Ist83nZNiXESXhN3d98NLS8KbX2wcbnd0B+CqRyvnv
          GbE+CfzxPf/zTsexxpS3TlTR80vAYkubmtWIMG128QKBgQD/iQbZx2xhH6VjYWC6
          +kc03povTKTe/MKUySO7poWjJrGbajrkq7RcXdNCglVSXcKY/BvmgsWRqJc+Jh2z
          enFIcGOuO146FEAr3i4hGjtV01/ukgAl6Ko68gdxjyQLqrJ/bg0qQO57KEhRh5Tb
          mR5mIkG2j2Usr4Llc3LGXIH8VQKBgQD3SNaahwum8+8kXaxgmKwfOL64rM5fLQq3
          f0UGzKZkuRSqXJn9EKuE1rNKX4zNUBWJVF+C4bjRGLz1QRS7j2taqU4awLie+5Ak
          M4Ww8lzHd3uKf+ESCd8DU3TzD+dggtuw+OTqVZdJKA5Kfrbg72ZUyzH3p9Oj/zMu
          QWl3d6TU2wKBgQCaMZs6qoWRjcEE2Ou/p+pz0qcDR6JtE+RuV3kCcJdPPbgKae2j
          sqCg49To2zCVBRK5sdc8H0kMfcjVrbZaaNYWugrMRfKz5Shb0DPRsbyAK45FrT/9
          oAmojAdF1PQRPi17i3LSPmApXMNWvxNp91lKk/1HJfwNHNNFlYZ6f7PICQKBgQCq
          q2ryXCJ+p/11a/F8+eJR6ig37YzBw6SR4RUTDEwLWHIa4q6lKsw2crhrrGbRjWRP
          1BvXiVK1fg1sd+6HRQUjHZb6f+jsUVO6qJSs+5ltUdnCTWBZwtZYxVECMQfQZICc
          NCxKT6iKpUq3v50YwiIug8+IzhwUJB5+3kacXcc14QKBgQDpjYvwAPAq1Rru/Ew4
          hzisDSCY5CLE+X/6dvogWhJBmpaZBKDmUGi6AwK9rcwITZmlR/qU+2WqNdhHxa8S
          uSp1A6OmOHQHA3I+J4veI0kPB2Y0Z65CyfCYm9MsNkcyFYx4tRBSOzAdA+xrJCa4
          y5+KYGmXlaoRhFSq1VO8mGoihA==
          -----END PRIVATE KEY-----
    Ecc:
      - Metadata:
          KeyId: 800d5768-3fd7-4edd-a4b8-4c81c3e4c147
          KeyUsage: SIGN_VERIFY
          Description: ECC key with curve secp256r1
        PrivateKeyPem: |
          -----BEGIN EC PRIVATE KEY-----
          MHcCAQEEIMnOrUrXr8rwne7d8f01cfwmpS/w+K7jcyWmmeLDgWKaoAoGCCqGSM49
          AwEHoUQDQgAEYNMBBZ3h1ipuph1iO5k+yLvTs94UN71quXN3f0P/tprs2Fp2FEas
          M7m7XZ2xlDK3wcEAs1QEIoQjjwnhcptQ6A==
          -----END EC PRIVATE KEY-----
```
Above creates 2 asymmetric keys, both for sign/verify. Key size derived from PEM.
 - RSA key `ff275b92-0def-4dfc-b0f6-87c96b26c6c7` (2048 bits)
 - ECC key `800d5768-3fd7-4edd-a4b8-4c81c3e4c147` (256 bits)
 
`PrivateKeyPem` is multiline string — pipe `|` in YAML handles this. Format is PKCS8, generated via OpenSSL or similar.
See below for bash functions to generate asymmetric key seed format.

Signing key choice: ECC 256-bit = smallest signatures; RSA 2048-bit = cheaper per op, widely compatible.

## Configuration
Environment variables for LKMS config:

- **KMS_PORT**: Listen port. Default: 8080
- **KMS_ACCOUNT_ID**: Dummy AWS account ID. Default: 111122223333
- **KMS_REGION**: Dummy region. Default: eu-west-2
- **KMS_SEED_PATH**: Seeding file path. Default: `/init/seed.yaml`
- **KMS_DATA_PATH**: Database path.
- **KMS_LOG_LEVEL**: Log level (e.g., DEBUG, INFO, WARN, ERROR). Default: INFO
	- Docker default: `/data`
	- Native default: `/tmp/local-kms`

Warning: keys and aliases stored under ARN — identity includes both `KMS_ACCOUNT_ID` and `KMS_REGION`. Changing these makes pre-existing data inaccessible.

## Building from source

### Prerequisites

Tested with Go 1.26

### Install

#### Using git and make (recommended)

```sh
git clone https://github.com/DAcodedBEAT/local-kms.git
cd local-kms
make build
```

Binary created as `./local-kms`

#### Using Go directly

```sh
git clone https://github.com/DAcodedBEAT/local-kms.git
cd local-kms
go build -o local-kms ./cmd/local-kms
```

### Run

```sh
./local-kms
```

Runs on `http://localhost:8080` by default.

### Using LKMS with the CLI

More detail:
* [Using AWS KMS via the CLI with a Symmetric Key](https://nsmith.net/aws-kms-cli)
* [Using AWS KMS via the CLI with Elliptic Curve (ECC) Keys](https://nsmith.net/aws-kms-cli-ecc)

Examples use `awslocal`, which wraps `aws` with required endpoint.

e.g. These two commands equivalent:
```bash
aws kms create-key --endpoint=http://localhost:4599
and
awslocal kms create-key
```

#### Creating a Customer Master Key
```bash
awslocal kms create-key
```

#### Encrypt data
```bash
awslocal kms encrypt \
--key-id 0579fe9c-129b-490a-adb0-42589ac4a017 \
--plaintext "My Test String"
```

#### Decrypt Data
```bash
awslocal kms decrypt \
--ciphertext-blob fileb://encrypted.dat
```

#### Generate Data Key
```bash
awslocal kms generate-data-key \
--key-id 0579fe9c-129b-490a-adb0-42589ac4a017 \
--key-spec AES_128
```

#### Importing custom key material
```bash
key_id=${1}
wrappingAlg=${2:-RSAES_OAEP_SHA_1}
expirationModel=${3:-KEY_MATERIAL_DOES_NOT_EXPIRE}
validToInput=${4}

if [ "$wrappingAlg" == "RSAES_PKCS1_V1_5" ]; then
    echo "RSAES_PKCS1_V1_5 is not supported by this script. Please use RSAES_OAEP_SHA_[1|256]."
    exit 1
fi

if [ -z "$key_id" ]; then
    echo ""
    echo "Creating new External key"
    key_id=$(awslocal kms create-key --origin EXTERNAL | jq -r '.KeyMetadata.KeyId')
fi

echo ""
echo "Getting Parameters For Import"
importParams=$(awslocal kms get-parameters-for-import --key-id $key_id --wrapping-algorithm $wrappingAlg --wrapping-key-spec RSA_2048)

pubKeyBinFile=$(mktemp)
echo $importParams | jq -r '.PublicKey' | base64 --decode > $pubKeyBinFile

importTokenBinFile=$(mktemp)
echo $importParams | jq -r '.ImportToken' | base64 --decode > $importTokenBinFile

keyMaterial="KeyMaterial-${key_id}.txt"
if [ -f "$keyMaterial" ]; then
  echo ""
  echo "Found existing key material"
else
  echo ""
  echo "Generating key material"
  keyMaterialTmp=$(mktemp)
  openssl rand -out $keyMaterialTmp 32

  # If you want to re-import key material then you'll need to save
  # this file and use it for any subsequent calls to Local KMS
  mv $keyMaterialTmp $keyMaterial
fi

echo ""
echo "Encrypting key material using public key"
encryptedKeyMaterial=$(mktemp)

openssl pkeyutl \
  -in $keyMaterial \
  -out $encryptedKeyMaterial \
  -inkey $pubKeyBinFile \
  -keyform DER \
  -pubin -encrypt \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha$(echo "$wrappingAlg" | sed -r 's/.*_([0-9]+)$/\1/')

validTo=
if [ -n "$validToInput" ]; then
    validTo=" --valid-to $validToInput"
fi

echo ""
echo "Import key material for key_id $key_id"
awslocal kms import-key-material --key-id $key_id \
    --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE \
    --import-token fileb://$importTokenBinFile \
    --encrypted-key-material fileb://$encryptedKeyMaterial \
    $validTo

echo ""
echo "Cleaning up"
rm -f $pubKeyBinFile
rm -f $importTokenBinFile 
rm -f $encryptedKeyMaterial

echo ""
echo "Describing new state"
awslocal kms describe-key --key-id $key_id
```

### Using LKMS with HTTP(ie)

#### Creating a Customer Master Key
```bash
http --json POST http://localhost:4599/ X-Amz-Target:TrentService.CreateKey
```
```json
{
    "KeyMetadata": {
        "AWSAccountId": "111122223333",
        "Arn": "arn:aws:kms:eu-west-2:111122223333:key/f154ba79-0b7d-4f19-9983-309f706ebc83",
        "CreationDate": 1571915850,
        "Enabled": true,
        "KeyId": "f154ba79-0b7d-4f19-9983-309f706ebc83",
        "KeyManager": "CUSTOMER",
        "KeyState": "Enabled",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "Origin": "AWS_KMS"
    }
}
```

#### Encrypting data (base64-encoded plaintext)
```bash
http --json POST http://localhost:4599/ X-Amz-Target:TrentService.Encrypt \
  KeyId=f154ba79-0b7d-4f19-9983-309f706ebc83 Plaintext='SGVsbG8='
```
```json
{
    "CiphertextBlob": "S2Fybjphd3M6a21zOmV1LXdlc3QtMjoxMTExMjIyMjMzMzM6a2V5L2YxNTRiYTc5...",
    "KeyId": "arn:aws:kms:eu-west-2:111122223333:key/f154ba79-0b7d-4f19-9983-309f706ebc83"
}
```

#### Decrypting ciphertext
```bash
http --json POST http://localhost:4599/ X-Amz-Target:TrentService.Decrypt \
  CiphertextBlob='S2Fybjphd3M6a21zOmV1LXdlc3QtMjoxMTExMjIyMjMzMzM6a2V5L2YxNTRiYTc5...'
```
```json
{
    "KeyId": "arn:aws:kms:eu-west-2:111122223333:key/f154ba79-0b7d-4f19-9983-309f706ebc83",
    "Plaintext": "SGVsbG8="
}
```
### Generating Asymmetric Keys in seed format
Two bash functions for generating seed-format keys in PKCS8, formatted for `seed.yaml`.

Requires `uuidgen` and `openssl`.

#### RSA Key Generation
```bash
function rsakey(){
local bits=$1
if ! [[ "$bits" =~ ^(2048|3072|4096)$ ]];
then
   echo "RSA keysize must be one of : 2048 3072 4096"
   return
fi


keyId=$(uuidgen | tr '[:upper:]' '[:lower:]')
echo "
Keys:
  Asymmetric:
    Rsa:
      - Metadata:
          KeyId: ${keyId}
          KeyUsage: SIGN_VERIFY # or ENCRYPT_DECRYPT
          Description: RSA key with ${bits} bits
        PrivateKeyPem: |
$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${bits} -pkeyopt rsa_keygen_pubexp:65537 | sed 's/^/          /')
"
}
````
Source then run — output pastes into `seed.yaml`:
```bash
rsakey 2048
rsakey 3072
rsakey 4096
```

#### ECC Key Generation 

```bash
function ecckey(){
local curve=$1
if ! [[ "$curve" =~ ^(secp256r1|secp384r1|secp521r1)$ ]];
then
   echo "Curve must be one of: secp256r1 secp384r1 secp521r1"
   return
fi
keyId=$(uuidgen | tr '[:upper:]' '[:lower:]')

echo "
Keys:
  Asymmetric:
    Ecc:
      - Metadata:
          KeyId: ${keyId}
          KeyUsage: SIGN_VERIFY
          Description: ECC key with curve ${curve}
        PrivateKeyPem: |
$(openssl ecparam -name ${curve} -genkey -noout | sed 's/^/          /')
"
}
```

Source then run — output pastes into `seed.yaml`:
```bash
ecckey secp256r1
ecckey secp384r1
ecckey secp521r1
```


## License

MIT License — see [LICENSE](LICENSE).
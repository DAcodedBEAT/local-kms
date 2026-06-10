package cmk

import (
	"crypto/rsa"
	"fmt"
	"github.com/nsmithuk/local-kms/src/config"
	"time"
)

//------------------------------------------

type KeyType int

const (
	TypeAes KeyType = iota
	TypeRsa
	TypeEcc
)

//---

type KeySpec string

const (
	SpecSymmetricDefault KeySpec = "SYMMETRIC_DEFAULT"
	SpecEccNistP256      KeySpec = "ECC_NIST_P256"
	SpecEccNistP384      KeySpec = "ECC_NIST_P384"
	SpecEccNistP521      KeySpec = "ECC_NIST_P521"
	SpecEccSecp256k1     KeySpec = "ECC_SECG_P256K1"
	SpecRsa2048          KeySpec = "RSA_2048"
	SpecRsa3072          KeySpec = "RSA_3072"
	SpecRsa4096          KeySpec = "RSA_4096"
)

//---

type EncryptionAlgorithm string

const (
	EncryptionAlgorithmAes           EncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	EncryptionAlgorithmRsaOaepSha1   EncryptionAlgorithm = "RSAES_OAEP_SHA_1"
	EncryptionAlgorithmRsaOaepSha256 EncryptionAlgorithm = "RSAES_OAEP_SHA_256"
)

//---

type SigningAlgorithm string

const (
	SigningAlgorithmEcdsaSha256   SigningAlgorithm = "ECDSA_SHA_256"
	SigningAlgorithmEcdsaSha384   SigningAlgorithm = "ECDSA_SHA_384"
	SigningAlgorithmEcdsaSha512   SigningAlgorithm = "ECDSA_SHA_512"
	SigningAlgorithmRsaPssSha256  SigningAlgorithm = "RSASSA_PSS_SHA_256"
	SigningAlgorithmRsaPssSha384  SigningAlgorithm = "RSASSA_PSS_SHA_384"
	SigningAlgorithmRsaPssSha512  SigningAlgorithm = "RSASSA_PSS_SHA_512"
	SigningAlgorithmRsaPkcsSha256 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_256"
	SigningAlgorithmRsaPkcsSha384 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_384"
	SigningAlgorithmRsaPkcsSha512 SigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_512"
)

//---

type KeyState string

const (
	KeyStateEnabled         KeyState = "Enabled"
	KeyStateDisabled        KeyState = "Disabled"
	KeyStatePendingImport   KeyState = "PendingImport"
	KeyStatePendingDeletion KeyState = "PendingDeletion"
	KeyStateUnavailable     KeyState = "Unavailable"
)

//---

type KeyUsage string

const (
	UsageEncryptDecrypt KeyUsage = "ENCRYPT_DECRYPT"
	UsageSignVerify     KeyUsage = "SIGN_VERIFY"
)

//---

type KeyOrigin string

const (
	KeyOriginAwsKms      KeyOrigin = "AWS_KMS"
	KeyOriginExternal    KeyOrigin = "EXTERNAL"
	KeyOriginAwsCloudHsm KeyOrigin = "AWS_CLOUDHSM"
)

//---

type WrappingAlgorithm string

const (
	WrappingAlgorithmPkcs1V15  WrappingAlgorithm = "RSAES_PKCS1_V1_5"
	WrappingAlgorithmOaepSha1  WrappingAlgorithm = "RSAES_OAEP_SHA_1"
	WrappingAlgorithmOaepSh256 WrappingAlgorithm = "RSAES_OAEP_SHA_256"
)

//---

type ExpirationModel string

const (
	ExpirationModelKeyMaterialExpires       ExpirationModel = "KEY_MATERIAL_EXPIRES"
	ExpirationModelKeyMaterialDoesNotExpire ExpirationModel = "KEY_MATERIAL_DOES_NOT_EXPIRE"
)

//------------------------------------------

type Key interface {
	GetArn() string
	GetPolicy() string
	SetPolicy(policy string)
	GetKeyType() KeyType
	GetMetadata() *KeyMetadata
}

type SigningKey interface {
	Key
	Sign(digest []byte, algorithm SigningAlgorithm) ([]byte, error)
	HashAndSign(message []byte, algorithm SigningAlgorithm) ([]byte, error)
	Verify(signature []byte, digest []byte, algorithm SigningAlgorithm) (bool, error)
	HashAndVerify(signature []byte, digest []byte, algorithm SigningAlgorithm) (bool, error)
}

//------------------------------------------

type BaseKey struct {
	Type     KeyType
	Metadata KeyMetadata
	Policy   string
}

func (k *BaseKey) SetPolicy(policy string) {
	k.Policy = policy
}

type KeyMetadata struct {
	AWSAccountId    string          `json:",omitempty"`
	Arn             string          `json:",omitempty"`
	CreationDate    float64         `json:",omitempty"`
	DeletionDate    float64         `json:",omitempty"`
	Description     string          `yaml:"Description"`
	Enabled         bool            `yaml:"Enabled"`
	ExpirationModel ExpirationModel `json:",omitempty"`
	KeyId           string          `json:",omitempty" yaml:"KeyId"`
	KeyManager      string          `json:",omitempty"`
	KeyState        KeyState        `json:",omitempty"`
	KeyUsage        KeyUsage        `json:",omitempty" yaml:"KeyUsage"`
	MultiRegion     bool            `json:"MultiRegion" yaml:"-"`
	Origin          KeyOrigin       `json:",omitempty" yaml:"Origin"`
	ValidTo         float64         `json:",omitempty"`

	SigningAlgorithms     []SigningAlgorithm    `json:",omitempty"`
	EncryptionAlgorithms  []EncryptionAlgorithm `json:",omitempty"`
	MacAlgorithms         []string              `json:",omitempty"`
	KeySpec               KeySpec               `json:",omitempty"`
	CustomerMasterKeySpec KeySpec               `json:",omitempty"`
}

type ParametersForImport struct {
	ParametersValidTo int64
	ImportToken       []byte
	PrivateKey        rsa.PrivateKey
	WrappingAlgorithm WrappingAlgorithm
}

type UnmarshalYAMLError struct {
	message string
	cause   error
}

func (e *UnmarshalYAMLError) Error() string {
	return fmt.Sprintf("Error unmarshaling YAML: %s", e.message)
}

func (e *UnmarshalYAMLError) Unwrap() error {
	return e.cause
}

func (m *KeyMetadata) IsPendingDeletion() bool {
	return m.DeletionDate != 0 && m.DeletionDate < float64(time.Now().Unix())
}

func (m *KeyMetadata) Initialize(keyId string) {
	m.KeyId = keyId
	m.Arn = config.ArnPrefix() + "key/" + keyId
	m.AWSAccountId = config.AWSAccountId
	m.CreationDate = float64(time.Now().UnixNano()) / 1e9
	m.Enabled = true
	m.KeyManager = "CUSTOMER"
	m.KeyState = KeyStateEnabled
	if m.Origin == "" {
		m.Origin = KeyOriginAwsKms
	}
}

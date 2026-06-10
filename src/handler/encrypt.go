package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

// rsaMaxPlaintextBytes returns the maximum plaintext size in bytes for the given
// RSA key spec and encryption algorithm.
//   - OAEP-SHA-1:   keyBytes - 2*hashLen(20) - 2  = keyBytes - 42
//   - OAEP-SHA-256: keyBytes - 2*hashLen(32) - 2  = keyBytes - 66
func rsaMaxPlaintextBytes(spec cmk.KeySpec, algo cmk.EncryptionAlgorithm) int {
	var keyBytes int
	switch spec {
	case cmk.SpecRsa2048:
		keyBytes = 256
	case cmk.SpecRsa3072:
		keyBytes = 384
	case cmk.SpecRsa4096:
		keyBytes = 512
	default:
		return -1
	}
	switch algo {
	case cmk.EncryptionAlgorithmRsaOaepSha1:
		return keyBytes - 42
	case cmk.EncryptionAlgorithmRsaOaepSha256:
		return keyBytes - 66
	default:
		return -1
	}
}

func (r *RequestHandler) Encrypt() Response {

	var body *kms.EncryptInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.EncryptInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if len(body.Plaintext) == 0 {
		msg := "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: Member must have " +
			"length greater than or equal to 1"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if len(body.Plaintext) > 4096 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'Plaintext' failed to satisfy "+
			"constraint: Member must have minimum length of 1 and maximum length of 4096.", string(body.Plaintext))

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.EncryptionAlgorithm == "" {
		body.EncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	}

	//----------------------------------

	key, response := r.getUsableKey(*body.KeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	//----------------------------------

	var cipherResponse []byte

	switch k := key.(type) {
	case *cmk.AesKey:

		cipherResponse, err = k.EncryptAndPackage(body.Plaintext, body.EncryptionContext)
		if err != nil {
			r.logger.Error(err.Error())
			return NewInternalFailureExceptionResponse(err.Error())
		}

	case *cmk.RsaKey:

		if k.GetMetadata().KeyUsage != cmk.UsageEncryptDecrypt {
			msg := fmt.Sprintf("%s key usage is %s which is not valid for Encrypt.", k.GetArn(), k.GetMetadata().KeyUsage)
			r.logger.Warnf(msg)
			return NewInvalidKeyUsageException(msg)
		}

		algo := cmk.EncryptionAlgorithm(body.EncryptionAlgorithm)
		if maxBytes := rsaMaxPlaintextBytes(k.GetMetadata().KeySpec, algo); maxBytes > 0 && len(body.Plaintext) > maxBytes {
			msg := fmt.Sprintf("Plaintext is too long for the chosen RSA public key. The plaintext must be no longer than %d bytes for %s with %s.", maxBytes, k.GetMetadata().KeySpec, algo)
			r.logger.Warnf(msg)
			return NewInvalidKeyUsageException(msg)
		}

		cipherResponse, err = k.Encrypt(body.Plaintext, cmk.EncryptionAlgorithm(body.EncryptionAlgorithm))
		if err != nil {
			r.logger.Error(err.Error())
			return NewInternalFailureExceptionResponse(err.Error())
		}

	default:

		if k.GetMetadata().KeyUsage == cmk.UsageSignVerify {
			msg := fmt.Sprintf("%s key usage is SIGN_VERIFY which is not valid for Encrypt.", k.GetArn())
			r.logger.Warnf(msg)
			return NewInvalidKeyUsageException(msg)
		}

		return NewInternalFailureExceptionResponse("key type not yet supported for encryption")
	}

	//---

	r.logger.Infof("Encryption called: %s\n", key.GetArn())

	return NewResponse(200, &struct {
		KeyId               string
		CiphertextBlob      []byte
		EncryptionAlgorithm cmk.EncryptionAlgorithm
	}{
		KeyId:               key.GetArn(),
		CiphertextBlob:      cipherResponse,
		EncryptionAlgorithm: cmk.EncryptionAlgorithm(body.EncryptionAlgorithm),
	})
}

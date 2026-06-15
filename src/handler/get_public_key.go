package handler

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/x509"
)

func (r *RequestHandler) GetPublicKey() Response {

	var body *kms.GetPublicKeyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.GetPublicKeyInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		return r.nullValidationResponse("KeyId")
	}

	key, response := r.getUsableKey(*body.KeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	//---

	var publicKey []byte

	switch k := key.(type) {
	case *cmk.RsaKey:

		publicKey, err = x509.MarshalPKIXPublicKey(&k.PrivateKey.PublicKey)
		if err != nil {
			r.logger.ErrorContext(r.request.Context(), "failed to marshal RSA public key", "error", err)
			return NewInternalFailureExceptionResponse(err.Error())
		}

	case *cmk.EccKey:

		privateKey := ecdsa.PrivateKey(k.PrivateKey)

		publicKey, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			r.logger.ErrorContext(r.request.Context(), "failed to marshal EC public key", "error", err)
			return NewInternalFailureExceptionResponse(err.Error())
		}

	default:
		msg := fmt.Sprintf("Key '%s' does not support returning a public key", key.GetArn())
		r.logger.WarnContext(r.request.Context(), "key does not support public key export", "keyArn", key.GetArn())
		return NewInvalidKeyUsageException(msg)
	}

	r.logger.DebugContext(r.request.Context(), "Public key returned", "keyArn", key.GetArn())

	return NewResponse(200, &struct {
		KeyId                 string
		CustomerMasterKeySpec cmk.KeySpec
		KeySpec               cmk.KeySpec
		EncryptionAlgorithms  []cmk.EncryptionAlgorithm `json:",omitempty"`
		SigningAlgorithms     []cmk.SigningAlgorithm    `json:",omitempty"`
		KeyUsage              cmk.KeyUsage
		PublicKey             []byte
	}{
		KeyId:                 key.GetArn(),
		CustomerMasterKeySpec: key.GetMetadata().CustomerMasterKeySpec,
		KeySpec:               key.GetMetadata().KeySpec,
		EncryptionAlgorithms:  key.GetMetadata().EncryptionAlgorithms,
		SigningAlgorithms:     key.GetMetadata().SigningAlgorithms,
		KeyUsage:              key.GetMetadata().KeyUsage,
		PublicKey:             publicKey,
	})
}

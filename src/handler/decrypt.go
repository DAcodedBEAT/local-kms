package handler

import (
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/service"
)

func (r *RequestHandler) Decrypt() Response {

	var body *kms.DecryptInput
	err := r.decodeBodyInto(&body)

	if err != nil {

		// Errors decoding the base64 have a specific error.
		_, ok := err.(base64.CorruptInputError)
		if ok {
			r.logger.WarnContext(r.request.Context(), "Unable to decode base64 value")
			return NewSerializationExceptionResponse("")
		}

		body = &kms.DecryptInput{}
	}

	//--------------------------------
	// Validation

	if len(body.CiphertextBlob) == 0 {
		msg := "1 validation error detected: Value at 'ciphertextBlob' failed to satisfy constraint: Member must " +
			"have length greater than or equal to 1"

		r.logger.WarnContext(r.request.Context(), "validation failed", "field", "CiphertextBlob", "error", "must have length greater than or equal to 1")
		return NewValidationExceptionResponse(msg)
	}

	if len(body.CiphertextBlob) > 6144 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'CiphertextBlob' failed to satisfy "+
			"constraint: Member must have length minimum length of 1 and maximum length of 6144.", string(body.CiphertextBlob))

		r.logger.WarnContext(r.request.Context(), "validation failed", "ciphertextBlobLength", len(body.CiphertextBlob))
		return NewValidationExceptionResponse(msg)
	}

	if body.EncryptionAlgorithm == "" {
		body.EncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	}

	//--------------------------------

	// If a KeyId is provided, we always use that, even for symmetric keys.
	var key cmk.Key
	var response Response
	var keyVersion uint32

	// We default of the full CiphertextBlob
	// Replaced later in the case of AES payloads
	ciphertext := body.CiphertextBlob

	if body.KeyId != nil {
		key, response = r.getUsableKey(*body.KeyId)

		// If the response is not empty, there was an error
		if !response.Empty() {
			return response
		}
	}

	/*
		We need to unpack the payload if either:
		- We don't already have a valid key; or
		- We do have a valid key, and it's of type AES.
	*/
	if _, isAes := key.(*cmk.AesKey); key == nil || isAes {

		var keyArn string
		var ok bool

		keyArn, keyVersion, ciphertext, ok = service.UnpackCiphertextBlob(body.CiphertextBlob)

		// If we unable to deconstruct the message
		if !ok {
			r.logger.WarnContext(r.request.Context(), "Unable to deconstruct ciphertext")
			return NewInvalidCiphertextExceptionResponse("")
		}

		// We only use the unpacked keyArn if a key wasn't supplied.
		if key == nil {
			key, response = r.getUsableKey(keyArn)
		} else if key.GetArn() != keyArn {
			// Explicit KeyId was supplied but doesn't match the key embedded in the blob.
			// AWS returns AccessDeniedException to avoid leaking key-existence metadata.
			msg := "The ciphertext refers to a customer master key that does not exist, does not exist in this region, " +
				"or you are not allowed to access."
			return NewAccessDeniedExceptionResponse(msg)
		}
	}

	// If the response is not empty, there was an error
	if key == nil || !response.Empty() {

		// We override the returned error on decrypt. The message is more generic such that it doesn't leak any metadata.
		msg := "The ciphertext refers to a customer master key that does not exist, does not exist in this region, " +
			"or you are not allowed to access."

		return NewAccessDeniedExceptionResponse(msg)
	}

	//--------------------------------

	var plaintext []byte

	switch k := key.(type) {
	case *cmk.AesKey:

		plaintext, err = k.Decrypt(keyVersion, ciphertext, body.EncryptionContext)
		if err != nil {
			r.logger.WarnContext(r.request.Context(), "unable to decode ciphertext", "error", err)

			return NewInvalidCiphertextExceptionResponse("")
		}

	case *cmk.RsaKey:

		if k.GetMetadata().KeyUsage != cmk.UsageEncryptDecrypt {
			msg := fmt.Sprintf("%s key usage is %s which is not valid for Decrypt.", k.GetArn(), k.GetMetadata().KeyUsage)
			r.logger.WarnContext(r.request.Context(), "invalid key usage", "keyArn", k.GetArn(), "keyUsage", k.GetMetadata().KeyUsage)
			return NewInvalidKeyUsageException(msg)
		}

		plaintext, err = k.Decrypt(ciphertext, cmk.EncryptionAlgorithm(body.EncryptionAlgorithm))
		if err != nil {
			r.logger.WarnContext(r.request.Context(), "unable to decode ciphertext", "error", err)

			return NewInvalidCiphertextExceptionResponse("")
		}

	default:
		return NewInternalFailureExceptionResponse("key type not yet supported for decryption")
	}

	//--------------------------------

	r.logger.InfoContext(r.request.Context(), "Decrypted", "keyArn", key.GetArn())

	return NewResponse(200, &struct {
		KeyId               string
		Plaintext           []byte
		EncryptionAlgorithm cmk.EncryptionAlgorithm
	}{
		KeyId:               key.GetArn(),
		Plaintext:           plaintext,
		EncryptionAlgorithm: cmk.EncryptionAlgorithm(body.EncryptionAlgorithm),
	})
}

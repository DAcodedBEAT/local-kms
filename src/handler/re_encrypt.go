package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/service"
)

func (r *RequestHandler) ReEncrypt() Response {

	var body *kms.ReEncryptInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.ReEncryptInput{}
	}

	//--------------------------------
	// Validation

	if body.DestinationKeyId == nil {
		msg := "DestinationKeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "DestinationKeyId")
		return NewMissingParameterResponse(msg)
	}

	if len(body.CiphertextBlob) == 0 {
		msg := "CiphertextBlob is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "CiphertextBlob")
		return NewMissingParameterResponse(msg)
	}

	if len(body.CiphertextBlob) > 6144 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'CiphertextBlob' failed to satisfy "+
			"constraint: Member must have length minimum length of 1 and maximum length of 6144.", string(body.CiphertextBlob))

		r.logger.WarnContext(r.request.Context(), "validation failed", "ciphertextBlobLength", len(body.CiphertextBlob))
		return NewValidationExceptionResponse(msg)
	}

	if body.SourceEncryptionAlgorithm == "" {
		body.SourceEncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	}

	if body.DestinationEncryptionAlgorithm == "" {
		body.DestinationEncryptionAlgorithm = "SYMMETRIC_DEFAULT"
	}

	//--------------------------------
	// Decrypt

	keyArn, keySourceVersion, ciphertext, _ := service.UnpackCiphertextBlob(body.CiphertextBlob)

	// If a SourceKeyId was provided, use it. Otherwise use the one from the blob.
	if body.SourceKeyId != nil {
		keyArn = *body.SourceKeyId
	}

	keySource, response := r.getUsableKey(keyArn)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	if keySource.GetMetadata().KeyUsage != cmk.UsageEncryptDecrypt {
		msg := fmt.Sprintf("%s key usage is %s which is not valid for Decrypt (via ReEncrypt).", keySource.GetArn(), keySource.GetMetadata().KeyUsage)
		r.logger.WarnContext(r.request.Context(), "invalid key usage", "keyArn", keySource.GetArn(), "keyUsage", keySource.GetMetadata().KeyUsage)
		return NewInvalidKeyUsageException(msg)
	}

	//---

	var plaintext []byte

	switch k := keySource.(type) {
	case *cmk.AesKey:

		plaintext, err = k.Decrypt(keySourceVersion, ciphertext, body.SourceEncryptionContext)
		if err != nil {
			r.logger.WarnContext(r.request.Context(), "unable to decode ciphertext", "error", err)

			return NewInvalidCiphertextExceptionResponse("")
		}

	case *cmk.RsaKey:

		plaintext, err = k.Decrypt(body.CiphertextBlob, cmk.EncryptionAlgorithm(body.SourceEncryptionAlgorithm))
		if err != nil {
			r.logger.WarnContext(r.request.Context(), "unable to decode ciphertext", "error", err)

			return NewInvalidCiphertextExceptionResponse("")
		}

	default:
		return NewInternalFailureExceptionResponse("key type not yet supported for decryption")
	}

	//--------------------------------
	// Encrypt

	keyDestination, response := r.getUsableKey(*body.DestinationKeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	if keyDestination.GetMetadata().KeyUsage != cmk.UsageEncryptDecrypt {
		msg := fmt.Sprintf("%s key usage is %s which is not valid for ReEncrypt.", keyDestination.GetArn(), keyDestination.GetMetadata().KeyUsage)
		r.logger.WarnContext(r.request.Context(), "invalid key usage", "keyArn", keyDestination.GetArn(), "keyUsage", keyDestination.GetMetadata().KeyUsage)
		return NewInvalidKeyUsageException(msg)
	}

	//---

	var cipherResponse []byte

	switch k := keyDestination.(type) {
	case *cmk.AesKey:

		cipherResponse, err = k.EncryptAndPackage(plaintext, body.DestinationEncryptionContext)
		if err != nil {
			r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
			return NewInternalFailureExceptionResponse(err.Error())
		}

	case *cmk.RsaKey:

		cipherResponse, err = k.Encrypt(plaintext, cmk.EncryptionAlgorithm(body.DestinationEncryptionAlgorithm))
		if err != nil {
			r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
			return NewInternalFailureExceptionResponse(err.Error())
		}

	default:
		return NewInternalFailureExceptionResponse("key type not yet supported for encryption")
	}

	//---

	r.logger.InfoContext(r.request.Context(), "ReEncrypt", "sourceKeyArn", keySource.GetArn(), "destKeyArn", keyDestination.GetArn())

	return NewResponse(200, &struct {
		KeyId                          string
		SourceKeyId                    string
		CiphertextBlob                 []byte
		SourceEncryptionAlgorithm      cmk.EncryptionAlgorithm
		DestinationEncryptionAlgorithm cmk.EncryptionAlgorithm
	}{
		KeyId:                          keyDestination.GetArn(),
		SourceKeyId:                    keySource.GetArn(),
		CiphertextBlob:                 cipherResponse,
		SourceEncryptionAlgorithm:      cmk.EncryptionAlgorithm(body.SourceEncryptionAlgorithm),
		DestinationEncryptionAlgorithm: cmk.EncryptionAlgorithm(body.DestinationEncryptionAlgorithm),
	})
}

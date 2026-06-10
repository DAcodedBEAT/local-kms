package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) Sign() Response {

	var body *kms.SignInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.SignInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		return r.nullValidationResponse("keyId")
	}

	if body.Message == nil {
		return r.nullValidationResponse("Message")
	}

	if len(body.Message) == 0 {
		msg := "1 validation error detected: Value at 'Message' failed to satisfy constraint: Member must have length greater than or equal to 1"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "Message")
		return NewValidationExceptionResponse(msg)
	}

	if len(body.Message) > 4096 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'Message' failed to satisfy "+
			"constraint: Member must have minimum length of 1 and maximum length of 4096.", string(body.Message))

		r.logger.WarnContext(r.request.Context(), "validation failed", "messageLength", len(body.Message))
		return NewValidationExceptionResponse(msg)
	}

	if body.SigningAlgorithm == "" {
		return r.nullValidationResponse("SigningAlgorithm")
	}

	if body.MessageType == "" {
		body.MessageType = "RAW"
	}

	if body.MessageType != "RAW" && body.MessageType != "DIGEST" {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'messageType' failed to satisfy "+
			"constraint: Member must satisfy enum value set: [DIGEST, RAW]", body.MessageType)

		r.logger.WarnContext(r.request.Context(), "validation failed", "messageType", body.MessageType)
		return NewValidationExceptionResponse(msg)
	}

	//----------------------------------

	key, response := r.getUsableKey(*body.KeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	var signingKey cmk.SigningKey

	switch k := key.(type) {
	case *cmk.RsaKey:

		if k.GetMetadata().KeyUsage == cmk.UsageEncryptDecrypt {
			msg := fmt.Sprintf("%s key usage is ENCRYPT_DECRYPT which is not valid for signing.", k.GetArn())
			r.logger.WarnContext(r.request.Context(), "invalid key usage", "keyArn", k.GetArn(), "keyUsage", k.GetMetadata().KeyUsage)
			return NewInvalidKeyUsageException(msg)
		}

		signingKey = k
	case *cmk.EccKey:

		if k.GetMetadata().KeyUsage == cmk.UsageEncryptDecrypt {
			msg := fmt.Sprintf("%s key usage is ENCRYPT_DECRYPT which is not valid for signing.", k.GetArn())
			r.logger.WarnContext(r.request.Context(), "invalid key usage", "keyArn", k.GetArn(), "keyUsage", k.GetMetadata().KeyUsage)
			return NewInvalidKeyUsageException(msg)
		}

		signingKey = k
	default:
		msg := fmt.Sprintf("%s key usage is ENCRYPT_DECRYPT which is not valid for Sign.", k.GetArn())
		r.logger.WarnContext(r.request.Context(), "invalid key usage", "keyArn", k.GetArn())
		return NewInvalidKeyUsageException(msg)
	}

	//---

	var result []byte

	if body.MessageType == "DIGEST" {
		result, err = signingKey.Sign(body.Message, cmk.SigningAlgorithm(body.SigningAlgorithm))
	} else {
		result, err = signingKey.HashAndSign(body.Message, cmk.SigningAlgorithm(body.SigningAlgorithm))
	}

	if err != nil {

		if _, ok := err.(*cmk.InvalidSigningAlgorithm); ok {
			msg := fmt.Sprintf("Algorithm %s is incompatible with key spec %s.", body.SigningAlgorithm, key.GetMetadata().CustomerMasterKeySpec)

			r.logger.WarnContext(r.request.Context(), "invalid algorithm", "algorithm", body.SigningAlgorithm, "keySpec", key.GetMetadata().CustomerMasterKeySpec)
			return NewInvalidKeyUsageException(msg)
		}

		if _, ok := err.(*cmk.InvalidDigestLength); ok {
			msg := fmt.Sprintf("Digest is invalid length for algorithm %s.", body.SigningAlgorithm)

			r.logger.WarnContext(r.request.Context(), "validation failed", "algorithm", body.SigningAlgorithm)
			return NewValidationExceptionResponse(msg)
		}

		r.logger.ErrorContext(r.request.Context(), "sign failed", "error", err)
		return NewInvalidKeyUsageException(err.Error())
	}

	//---

	r.logger.InfoContext(r.request.Context(), "Sign", "messageType", body.MessageType, "algorithm", signingKey.GetMetadata().CustomerMasterKeySpec, "keyArn", key.GetArn())

	return NewResponse(200, &struct {
		KeyId            string
		Signature        []byte
		SigningAlgorithm cmk.SigningAlgorithm
	}{
		KeyId:            key.GetArn(),
		Signature:        result,
		SigningAlgorithm: cmk.SigningAlgorithm(body.SigningAlgorithm),
	})
}

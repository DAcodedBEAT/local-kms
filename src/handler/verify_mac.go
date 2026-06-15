package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) VerifyMac() Response {

	var body *kms.VerifyMacInput
	if err := r.decodeBodyInto(&body); err != nil {
		body = &kms.VerifyMacInput{}
	}

	//---

	if body.KeyId == nil {
		return r.nullValidationResponse("keyId")
	}

	if body.Message == nil {
		return r.nullValidationResponse("message")
	}

	if body.Mac == nil {
		return r.nullValidationResponse("mac")
	}

	if body.MacAlgorithm == "" {
		return r.nullValidationResponse("macAlgorithm")
	}

	//--------------------------------
	// Get the key

	key, response := r.getUsableKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	if key.GetMetadata().KeyState != cmk.KeyStateEnabled {
		return NewDisabledExceptionResponse("")
	}

	if key.GetKeyType() != cmk.TypeHmac {
		msg := fmt.Sprintf("The key usage %s is not valid for this operation.", key.GetMetadata().KeyUsage)
		r.logger.WarnContext(r.request.Context(), "invalid key usage", "keyArn", key.GetArn(), "keyUsage", key.GetMetadata().KeyUsage)
		return NewValidationExceptionResponse(msg)
	}

	//---

	algorithm := string(body.MacAlgorithm)
	supportedAlgorithms := key.GetMetadata().SigningAlgorithms
	algorithmSupported := false
	for _, alg := range supportedAlgorithms {
		if string(alg) == algorithm {
			algorithmSupported = true
			break
		}
	}

	if !algorithmSupported {
		msg := fmt.Sprintf("The request is not valid for the key spec %s.", key.GetMetadata().KeySpec)
		r.logger.WarnContext(r.request.Context(), "invalid mac algorithm", "algorithm", algorithm, "keySpec", key.GetMetadata().KeySpec)
		return NewValidationExceptionResponse(msg)
	}

	//---

	macKey, ok := key.(cmk.MacKey)
	if !ok {
		msg := "Key does not support MAC operations"
		r.logger.WarnContext(r.request.Context(), "key does not support MAC operations", "keyArn", key.GetArn())
		return NewValidationExceptionResponse(msg)
	}

	//---

	macValid, err := macKey.VerifyMac(body.Message, body.Mac, cmk.SigningAlgorithm(algorithm))
	if err != nil {
		r.logger.ErrorContext(r.request.Context(), "verify mac failed", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	keyArn := key.GetArn()
	r.logger.InfoContext(r.request.Context(), "MAC verified", "keyArn", keyArn, "algorithm", algorithm, "valid", macValid)

	return NewResponse(200, &kms.VerifyMacOutput{
		KeyId:        &keyArn,
		MacValid:     macValid,
		MacAlgorithm: body.MacAlgorithm,
	})
}

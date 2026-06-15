package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) GenerateMac() Response {

	var body *kms.GenerateMacInput
	if err := r.decodeBodyInto(&body); err != nil {
		body = &kms.GenerateMacInput{}
	}

	//---

	if body.KeyId == nil {
		return r.nullValidationResponse("keyId")
	}

	if body.Message == nil {
		return r.nullValidationResponse("message")
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

	mac, err := macKey.GenerateMac(body.Message, cmk.SigningAlgorithm(algorithm))
	if err != nil {
		r.logger.ErrorContext(r.request.Context(), "generate mac failed", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	keyArn := key.GetArn()
	r.logger.InfoContext(r.request.Context(), "MAC generated", "keyArn", keyArn, "algorithm", algorithm)

	return NewResponse(200, &kms.GenerateMacOutput{
		KeyId:        &keyArn,
		Mac:          mac,
		MacAlgorithm: body.MacAlgorithm,
	})
}

package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) PutKeyPolicy() Response {

	var body *kms.PutKeyPolicyInput
	err := r.decodeBodyInto(&body)

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		return r.nullValidationResponse("keyId")
	}

	if body.Policy == nil {
		return r.nullValidationResponse("policy")
	}

	//---
	policyName := "default"
	if body.PolicyName != nil {
		policyName = *body.PolicyName
	}

	if policyName != "default" {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'policyName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w]+", policyName)

		r.logger.WarnContext(r.request.Context(), "validation failed", "policyName", policyName)
		return NewValidationExceptionResponse(msg)
	}

	if len(*body.Policy) > 32768 {
		msg := "1 validation error detected: Value at 'policy' failed to satisfy constraint: Member must have length less than or equal to 32768"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "Policy")
		return NewValidationExceptionResponse(msg)
	}

	//---

	keyArn := config.EnsureArn("key/", *body.KeyId)

	// Lookup the key
	key, _ := r.database.LoadKey(keyArn)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", keyArn)

		r.logger.WarnContext(r.request.Context(), "key not found", "keyArn", keyArn)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	key.SetPolicy(*body.Policy)

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.InfoContext(r.request.Context(), "Key policy set", "keyArn", key.GetArn())

	return NewResponse(200, nil)
}

package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) PutKeyPolicy() Response {

	var body *kms.PutKeyPolicyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.PutKeyPolicyInput{}
	}

	if body.KeyId == nil {
		msg := "1 validation error detected: Value null at 'keyId' failed to satisfy constraint: Member must not be null"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.Policy == nil {
		msg := "1 validation error detected: Value null at 'policy' failed to satisfy constraint: Member must not be null"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	policyName := "default"
	if body.PolicyName != nil {
		policyName = *body.PolicyName
	}

	if policyName != "default" {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'policyName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w]+", policyName)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if len(*body.Policy) > 32768 {
		msg := "1 validation error detected: Value at 'policy' failed to satisfy constraint: Member must have length less than or equal to 32768"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	//---

	keyArn := config.EnsureArn("key/", *body.KeyId)

	// Lookup the key
	key, _ := r.database.LoadKey(keyArn)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", keyArn)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	key.SetPolicy(*body.Policy)

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.Infof("New Key Policy set for: %s\n", key.GetArn())

	return NewResponse(200, nil)
}

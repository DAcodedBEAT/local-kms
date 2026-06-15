package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) GetKeyPolicy() Response {

	var body *kms.GetKeyPolicyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.GetKeyPolicyInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "KeyId")
		return NewMissingParameterResponse(msg)
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

	r.logger.DebugContext(r.request.Context(), "Key policy returned", "keyArn", key.GetArn())

	return NewResponse(200, map[string]string{
		"Policy":     key.GetPolicy(),
		"PolicyName": "default",
	})
}

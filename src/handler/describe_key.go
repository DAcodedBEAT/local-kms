package handler

import (
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) DescribeKey() Response {

	var body *kms.DescribeKeyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.DescribeKeyInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "field", "KeyId", "error", "required parameter")
		return NewMissingParameterResponse(msg)
	}

	//---

	key, response := r.getKey(*body.KeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response
	}

	//---

	r.logger.DebugContext(r.request.Context(), "Key described", "keyArn", key.GetArn())

	return NewResponse(200, map[string]*cmk.KeyMetadata{
		"KeyMetadata": key.GetMetadata(),
	})
}

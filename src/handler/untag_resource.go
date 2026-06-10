package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) UntagResource() Response {

	var body *kms.UntagResourceInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.UntagResourceInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		return r.nullValidationResponse("keyId")
	}

	if body.TagKeys == nil {
		return r.nullValidationResponse("tagKeys")
	}

	//---

	key, response := r.getKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	switch key.GetMetadata().KeyState {
	case cmk.KeyStatePendingDeletion:
		msg := fmt.Sprintf("%s is pending deletion.", *body.KeyId)

		r.logger.WarnContext(r.request.Context(), "key pending deletion", "keyId", *body.KeyId)
		return NewKMSInvalidStateExceptionResponse(msg)

	}

	//---

	if len(body.TagKeys) > 0 {
		for _, k := range body.TagKeys {
			if err := r.database.DeleteObject(key.GetArn() + "/tag/" + k); err != nil {
				r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
				return NewInternalFailureExceptionResponse(err.Error())
			}
			r.logger.InfoContext(r.request.Context(), "Tag deleted", "tagKey", k)
		}
	}

	return NewResponse(200, nil)
}

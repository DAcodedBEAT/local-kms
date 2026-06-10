package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) DisableKey() Response {

	var body *kms.DisableKeyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.DisableKeyInput{}
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
	if !response.Empty() {
		return response
	}

	//---

	switch key.GetMetadata().KeyState {
	case cmk.KeyStatePendingDeletion:
		msg := fmt.Sprintf("%s is pending deletion.", key.GetArn())
		r.logger.WarnContext(r.request.Context(), "key pending deletion", "keyArn", key.GetArn())
		return NewKMSInvalidStateExceptionResponse(msg)

	case cmk.KeyStatePendingImport:
		msg := fmt.Sprintf("%s is pending import.", key.GetArn())
		r.logger.WarnContext(r.request.Context(), "key pending import", "keyArn", key.GetArn())
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	key.GetMetadata().Enabled = false
	key.GetMetadata().KeyState = cmk.KeyStateDisabled

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.InfoContext(r.request.Context(), "Key disabled", "keyArn", key.GetArn())

	return NewResponse(200, nil)

}

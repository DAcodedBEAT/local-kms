package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) CancelKeyDeletion() Response {

	var body *kms.CancelKeyDeletionInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.CancelKeyDeletionInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "field", "KeyId", "error", "required parameter")
		return NewMissingParameterResponse(msg)
	}

	//---

	target := config.EnsureArn("key/", *body.KeyId)

	// Lookup the key
	key, _ := r.database.LoadKey(target)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", target)

		r.logger.WarnContext(r.request.Context(), "key not found", "keyArn", target)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	if key.GetMetadata().KeyState != cmk.KeyStatePendingDeletion {
		msg := fmt.Sprintf("%s is not pending deletion.", target)

		r.logger.WarnContext(r.request.Context(), "invalid key state", "keyArn", target)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	key.GetMetadata().Enabled = false
	key.GetMetadata().KeyState = cmk.KeyStateDisabled
	key.GetMetadata().DeletionDate = 0

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.InfoContext(r.request.Context(), "Key deletion canceled", "keyArn", key.GetArn())

	return NewResponse(200, map[string]any{
		"KeyId": key.GetArn(),
	})
}

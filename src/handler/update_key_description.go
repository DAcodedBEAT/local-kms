package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) UpdateKeyDescription() Response {

	var body *kms.UpdateKeyDescriptionInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.UpdateKeyDescriptionInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "KeyId")
		return NewMissingParameterResponse(msg)
	}

	if body.Description == nil {
		d := ""
		body.Description = &d
	}

	if len(*body.Description) > 8192 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'description' failed to satisfy "+
			"constraint: Member must have length less than or equal to 8192", *body.Description)

		r.logger.WarnContext(r.request.Context(), "validation failed", "value", *body.Description)
		return NewValidationExceptionResponse(msg)
	}

	// --------------------------------

	keyArn := config.EnsureArn("key/", *body.KeyId)

	// Lookup the key
	key, _ := r.database.LoadKey(keyArn)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", keyArn)

		r.logger.WarnContext(r.request.Context(), "key not found", "keyArn", keyArn)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	if key.GetMetadata().DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", keyArn)

		r.logger.WarnContext(r.request.Context(), "key pending deletion", "keyArn", keyArn)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	key.GetMetadata().Description = *body.Description

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.InfoContext(r.request.Context(), "Key description updated", "keyArn", key.GetArn())

	return NewResponse(200, nil)
}

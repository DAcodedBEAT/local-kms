package handler

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) DisableKeyRotation() Response {

	var body *kms.DisableKeyRotationInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.DisableKeyRotationInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "field", "KeyId", "error", "required parameter")
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

	// Check the key supports rotation
	if key.GetMetadata().Origin == cmk.KeyOriginExternal {
		msg := fmt.Sprintf("%s origin is EXTERNAL which is not valid for this operation.", key.GetArn())

		r.logger.WarnContext(r.request.Context(), "unsupported operation", "keyArn", key.GetArn(), "origin", key.GetMetadata().Origin)
		return NewUnsupportedOperationException(msg)
	}

	if _, ok := key.(*cmk.AesKey); !ok {
		msg := fmt.Sprintf("Key '%s' does not support rotation", keyArn)
		r.logger.WarnContext(r.request.Context(), "unsupported operation", "keyArn", keyArn)
		return NewUnsupportedOperationException(msg)
	}

	//---

	if key.GetMetadata().DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", keyArn)

		r.logger.WarnContext(r.request.Context(), "key pending deletion", "keyArn", keyArn)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	if !key.GetMetadata().Enabled {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is disabled.", keyArn)

		r.logger.WarnContext(r.request.Context(), "key disabled", "keyArn", keyArn)
		return NewDisabledExceptionResponse(msg)
	}

	//---

	// Disable by setting this to Time Zero.
	key.(*cmk.AesKey).NextKeyRotation = time.Time{}

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.InfoContext(r.request.Context(), "Key rotation disabled", "keyArn", key.GetMetadata().Arn)

	return NewResponse(200, nil)
}

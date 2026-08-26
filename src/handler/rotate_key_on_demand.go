package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) RotateKeyOnDemand() Response {

	var body *kms.RotateKeyOnDemandInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.RotateKeyOnDemandInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "KeyId")
		return NewMissingParameterResponse(msg)
	}

	//---

	key, response := r.getKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	//---

	if key.GetMetadata().Origin == cmk.KeyOriginExternal {
		msg := fmt.Sprintf("%s origin is EXTERNAL which is not valid for this operation.", key.GetArn())

		r.logger.WarnContext(r.request.Context(), "unsupported operation", "keyArn", key.GetArn(), "origin", key.GetMetadata().Origin)
		return NewUnsupportedOperationException(msg)
	}

	aesKey, ok := key.(*cmk.AesKey)
	if !ok {
		msg := fmt.Sprintf("%s is not a symmetric encryption KMS key.", key.GetArn())

		r.logger.WarnContext(r.request.Context(), "unsupported operation", "keyArn", key.GetArn(), "reason", "key does not support on-demand rotation")
		return NewUnsupportedOperationException(msg)
	}

	//---

	if key.GetMetadata().DeletionDate != 0 {
		msg := fmt.Sprintf("%s is pending deletion.", key.GetArn())

		r.logger.WarnContext(r.request.Context(), "key pending deletion", "keyArn", key.GetArn())
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	if !key.GetMetadata().Enabled {
		msg := fmt.Sprintf("%s is disabled.", key.GetArn())

		r.logger.WarnContext(r.request.Context(), "key disabled", "keyArn", key.GetArn())
		return NewDisabledExceptionResponse(msg)
	}

	//---

	if err := aesKey.RotateOnDemand(); err != nil {
		msg := fmt.Sprintf("On-demand rotations quota exceeded for %s.", key.GetArn())

		r.logger.WarnContext(r.request.Context(), "on-demand rotation limit exceeded", "keyArn", key.GetArn())
		return NewLimitExceededExceptionResponse(msg)
	}

	//--------------------------------
	// Save the key

	if err := r.database.SaveKey(key); err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.InfoContext(r.request.Context(), "Key rotated on demand", "keyArn", key.GetArn())

	return NewResponse(200, &struct {
		KeyId string
	}{
		KeyId: key.GetArn(),
	})
}

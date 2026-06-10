package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

func (r *RequestHandler) DeleteImportedKeyMaterial() Response {
	var body *kms.DeleteImportedKeyMaterialInput
	if err := r.decodeBodyInto(&body); err != nil {
		r.logger.ErrorContext(r.request.Context(), "Failed to decode request", "error", err)
		body = &kms.DeleteImportedKeyMaterialInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "field", "KeyId", "error", "required parameter")
		return NewMissingParameterResponse(msg)
	}

	//---

	// Lookup the key

	key, response := r.getKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", key.GetArn())

		r.logger.WarnContext(r.request.Context(), "key not found", "keyArn", key.GetArn())
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	// Check key metadata

	keyMetadata := key.GetMetadata()
	if keyMetadata.Origin != cmk.KeyOriginExternal {
		msg := fmt.Sprintf("%s origin is %s which is not valid for this operation.", key.GetArn(), keyMetadata.Origin)

		r.logger.WarnContext(r.request.Context(), "unsupported operation", "keyArn", key.GetArn(), "origin", keyMetadata.Origin)
		return NewUnsupportedOperationException(msg)
	}

	switch keyMetadata.KeyState {
	case cmk.KeyStatePendingDeletion:
		msg := fmt.Sprintf("%s is pending deletion.", *body.KeyId)

		r.logger.WarnContext(r.request.Context(), "key pending deletion", "keyId", *body.KeyId)
		return NewKMSInvalidStateExceptionResponse(msg)

	case cmk.KeyStateUnavailable:
		msg := fmt.Sprintf("%s is unavailable.", *body.KeyId)

		r.logger.WarnContext(r.request.Context(), "invalid key state", "keyId", *body.KeyId)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	// We're good to go. Instead of actually deleting anything, we leave the imported
	// key material in place as any attempt to import key material again must import the
	// same key material again.
	keyMetadata.KeyState = cmk.KeyStatePendingImport
	keyMetadata.Enabled = false
	keyMetadata.ValidTo = 0
	keyMetadata.ExpirationModel = ""

	//--------------------------------
	// Save the key

	if err := r.database.SaveKey(key); err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	r.logger.InfoContext(r.request.Context(), "Key material deleted", "keyArn", key.GetArn())

	return NewResponse(200, &struct {
		KeyId string
	}{
		KeyId: key.GetArn(),
	})
}

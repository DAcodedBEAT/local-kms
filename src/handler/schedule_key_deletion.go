package handler

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) ScheduleKeyDeletion() Response {

	var body *kms.ScheduleKeyDeletionInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.ScheduleKeyDeletionInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "KeyId")
		return NewMissingParameterResponse(msg)
	}

	var pendingWindowInDays int64

	if body.PendingWindowInDays != nil {
		pendingWindowInDays = int64(*body.PendingWindowInDays)

		if pendingWindowInDays < 7 || pendingWindowInDays > 30 {
			msg := fmt.Sprintf("1 validation error detected: Value '%d' at 'PendingWindowInDays' failed to satisfy "+
				"constraint: Member must have minimum value of 7 and maximum value of 30.", *body.PendingWindowInDays)

			r.logger.WarnContext(r.request.Context(), "validation failed", "pendingWindowInDays", *body.PendingWindowInDays)
			return NewValidationExceptionResponse(msg)
		}
	} else {
		pendingWindowInDays = 30
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

	if key.GetMetadata().KeyState == cmk.KeyStatePendingDeletion {
		msg := fmt.Sprintf("%s is pending deletion.", target)

		r.logger.WarnContext(r.request.Context(), "key pending deletion", "keyArn", target)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	key.GetMetadata().Enabled = false
	key.GetMetadata().KeyState = cmk.KeyStatePendingDeletion
	key.GetMetadata().DeletionDate = float64(time.Now().AddDate(0, 0, int(pendingWindowInDays)).UnixNano()) / 1e9

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.InfoContext(r.request.Context(), "Key deletion scheduled", "keyArn", key.GetArn(), "deletionDate", key.GetMetadata().DeletionDate)

	return NewResponse(200, map[string]any{
		"KeyId":               key.GetArn(),
		"DeletionDate":        key.GetMetadata().DeletionDate,
		"KeyState":            key.GetMetadata().KeyState,
		"PendingWindowInDays": pendingWindowInDays,
	})
}

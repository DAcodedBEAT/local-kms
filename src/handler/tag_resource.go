package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
)

const maxTagsPerKey = 50

func (r *RequestHandler) TagResource() Response {

	var body *kms.TagResourceInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.TagResourceInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		return r.nullValidationResponse("keyId")
	}

	if body.Tags == nil {
		return r.nullValidationResponse("tags")
	}

	response := r.validateTags(body.Tags)
	if !response.Empty() {
		return response
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

	//--------------------------------
	// Enforce 50-tag quota

	if len(body.Tags) > 0 {
		currentCount, countErr := r.database.CountTags(key.GetArn())
		if countErr != nil {
			r.logger.ErrorContext(r.request.Context(), "internal error", "error", countErr)
			return NewInternalFailureExceptionResponse(countErr.Error())
		}

		// Determine how many of the incoming tags are new keys (not updates to existing ones)
		existingTags, listErr := r.database.ListTags(key.GetArn(), int64(currentCount)+1, "")
		if listErr != nil {
			r.logger.ErrorContext(r.request.Context(), "internal error", "error", listErr)
			return NewInternalFailureExceptionResponse(listErr.Error())
		}

		existingKeys := make(map[string]struct{}, len(existingTags))
		for _, t := range existingTags {
			existingKeys[t.TagKey] = struct{}{}
		}

		newCount := 0
		for _, kv := range body.Tags {
			if _, exists := existingKeys[*kv.TagKey]; !exists {
				newCount++
			}
		}

		if currentCount+newCount > maxTagsPerKey {
			msg := fmt.Sprintf("The request would add %d new tag(s) to key %s, which would exceed the maximum of %d tags per key.",
				newCount, key.GetArn(), maxTagsPerKey)
			r.logger.WarnContext(r.request.Context(), "validation failed", "keyArn", key.GetArn(), "tagCount", newCount)
			return New400ExceptionResponse("TagException", msg)
		}
	}

	//--------------------------------
	// Create the tags

	if response := r.saveTags(key, body.Tags); !response.Empty() {
		return response
	}

	return NewResponse(200, nil)
}

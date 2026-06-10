package handler

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/data"
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
		msg := "1 validation error detected: Value null at 'keyId' failed to satisfy constraint: Member must not be null"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	if body.Tags == nil {
		msg := "1 validation error detected: Value null at 'tags' failed to satisfy constraint: Member must not be null"

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	// Reject aws: prefix tags
	for _, kv := range body.Tags {
		if strings.HasPrefix(*kv.TagKey, "aws:") {
			msg := fmt.Sprintf("The tag key 'aws:' prefix is reserved for AWS use and cannot be used in customer-managed key tags.")
			r.logger.Warnf(msg)
			return New400ExceptionResponse("TagException", msg)
		}
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

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)

	}

	//--------------------------------
	// Enforce 50-tag quota

	if len(body.Tags) > 0 {
		currentCount, countErr := r.database.CountTags(key.GetArn())
		if countErr != nil {
			r.logger.Error(countErr)
			return NewInternalFailureExceptionResponse(countErr.Error())
		}

		// Determine how many of the incoming tags are new keys (not updates to existing ones)
		existingTags, listErr := r.database.ListTags(key.GetArn(), int64(currentCount)+1, "")
		if listErr != nil {
			r.logger.Error(listErr)
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
			r.logger.Warnf(msg)
			return New400ExceptionResponse("TagException", msg)
		}
	}

	//--------------------------------
	// Create the tags

	if len(body.Tags) > 0 {
		for _, kv := range body.Tags {
			t := &data.Tag{
				TagKey:   *kv.TagKey,
				TagValue: *kv.TagValue,
			}

			if err := r.database.SaveTag(key, t); err != nil {
				r.logger.Error(err)
				return NewInternalFailureExceptionResponse(err.Error())
			}

			r.logger.Infof("New tag created: %s / %s\n", t.TagKey, t.TagValue)
		}
	}

	//---

	return NewResponse(200, nil)
}

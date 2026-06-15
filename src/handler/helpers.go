package handler

import (
	"fmt"
	"strings"

	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
)

/*
Finds a key for a given key or alias name or ARN
*/
func (r *RequestHandler) getKey(keyId string) (cmk.Key, Response) {

	// If it's an alias, map it to a key
	if strings.Contains(keyId, "alias/") {
		aliasArn := config.EnsureArn("", keyId)

		alias, err := r.database.LoadAlias(aliasArn)

		if err != nil {
			msg := fmt.Sprintf("Alias %s is not found.", config.ArnPrefix()+keyId)

			r.logger.WarnContext(r.request.Context(), "alias not found", "aliasArn", config.ArnPrefix()+keyId)
			return nil, NewNotFoundExceptionResponse(msg)
		}

		keyId = alias.TargetKeyId
	}

	//---

	// Lookup the key
	keyId = config.EnsureArn("key/", keyId)

	key, _ := r.database.LoadKey(keyId)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", keyId)
		r.logger.WarnContext(r.request.Context(), "key not found", "keyArn", keyId)

		return nil, NewNotFoundExceptionResponse(msg)
	}

	return key, Response{}
}

/*
Finds a key for a given key or alias name or ARN
And confirms that it's available to use for cryptographic operations.
*/
func (r *RequestHandler) getUsableKey(keyId string) (cmk.Key, Response) {

	key, response := r.getKey(keyId)
	if key == nil {
		return nil, response
	}

	//----------------------------------

	if key.GetMetadata().KeyState == cmk.KeyStatePendingImport {
		msg := fmt.Sprintf("%s is pending import.", keyId)

		r.logger.WarnContext(r.request.Context(), "key pending import", "keyArn", key.GetArn())
		return nil, NewKMSInvalidStateExceptionResponse(msg)
	}

	if key.GetMetadata().DeletionDate != 0 {
		msg := fmt.Sprintf("%s is pending deletion.", keyId)

		r.logger.WarnContext(r.request.Context(), "key pending deletion", "keyArn", key.GetArn(), "deletionDate", key.GetMetadata().DeletionDate)
		return nil, NewKMSInvalidStateExceptionResponse(msg)
	}

	if !key.GetMetadata().Enabled {
		msg := fmt.Sprintf("%s is disabled.", keyId)

		r.logger.WarnContext(r.request.Context(), "key disabled", "keyArn", key.GetArn())
		return nil, NewDisabledExceptionResponse(msg)
	}

	return key, Response{}
}

func (r *RequestHandler) nullValidationResponse(field string) Response {
	msg := fmt.Sprintf("1 validation error detected: Value null at '%s' failed to satisfy constraint: Member must not be null", field)

	r.logger.WarnContext(r.request.Context(), "validation failed", "field", field, "error", "must not be null")
	return NewValidationExceptionResponse(msg)
}

func (r *RequestHandler) validateTags(tags []kmstypes.Tag) Response {

	// Reject aws: prefix tags
	for _, kv := range tags {
		if kv.TagKey != nil && strings.HasPrefix(*kv.TagKey, "aws:") {
			msg := "The tag key 'aws:' prefix is reserved for AWS use and cannot be used in customer-managed key tags."
			r.logger.WarnContext(r.request.Context(), "validation failed", "tagKey", *kv.TagKey, "error", "reserved prefix")
			return New400ExceptionResponse("TagException", msg)
		}
	}

	for i, kv := range tags {
		if kv.TagKey == nil || len(*kv.TagKey) < 1 {
			msg := fmt.Sprintf("1 validation error detected: Value '' at 'tags.%d.member.tagKey' failed to "+
				"satisfy constraint: Member must have length greater than or equal to 1", i+1)

			r.logger.WarnContext(r.request.Context(), "validation failed", "index", i+1, "field", "tagKey", "error", "too short")
			return NewValidationExceptionResponse(msg)
		}

		if len(*kv.TagKey) > 128 {
			msg := fmt.Sprintf("1 validation error detected: Value '' at 'tags.%d.member.tagKey' failed to "+
				"satisfy constraint: Member must have length less than or equal to 128", i+1)

			r.logger.WarnContext(r.request.Context(), "validation failed", "index", i+1, "field", "tagKey", "error", "too long", "length", len(*kv.TagKey))
			return NewValidationExceptionResponse(msg)
		}

		// TagValue must be set; empty string is allowed but max 256
		if kv.TagValue == nil || len(*kv.TagValue) > 256 {
			msg := fmt.Sprintf("1 validation error detected: Value '' at 'tags.%d.member.tagValue' failed to "+
				"satisfy constraint: Member must have length less than or equal to 256", i+1)

			r.logger.WarnContext(r.request.Context(), "validation failed", "index", i+1, "field", "tagValue", "error", "too long", "length", len(*kv.TagValue))
			return NewValidationExceptionResponse(msg)
		}
	}

	return Response{}
}

func (r *RequestHandler) saveTags(key cmk.Key, tags []kmstypes.Tag) Response {
	for _, kv := range tags {
		t := &data.Tag{
			TagKey:   *kv.TagKey,
			TagValue: *kv.TagValue,
		}

		if err := r.database.SaveTag(key, t); err != nil {
			r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
			return NewInternalFailureExceptionResponse(err.Error())
		}
	}
	if len(tags) > 0 {
		r.logger.InfoContext(r.request.Context(), "Tags created", "count", len(tags), "keyArn", key.GetArn())
	}
	return Response{}
}

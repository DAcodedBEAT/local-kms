package handler

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) UpdateAlias() Response {

	var body *kms.UpdateAliasInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.UpdateAliasInput{}
	}

	//--------------------------------
	// Validation

	if body.TargetKeyId == nil {
		msg := "TargetKeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "TargetKeyId")
		return NewMissingParameterResponse(msg)
	}

	if body.AliasName == nil {
		msg := "AliasName is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "AliasName")
		return NewMissingParameterResponse(msg)
	}

	if !strings.HasPrefix(*body.AliasName, "alias/") {
		msg := "Alias must start with the prefix \"alias/\". Please see " +
			"http://docs.aws.amazon.com/kms/latest/developerguide/programming-aliases.html"

		r.logger.WarnContext(r.request.Context(), msg)
		return NewValidationExceptionResponse(msg)
	}

	if strings.HasPrefix(*body.AliasName, "alias/aws") {
		r.logger.WarnContext(r.request.Context(), "Cannot create alias with aws/ prefix")
		return NewNotAuthorizedExceptionResponse("")
	}

	if len(*body.AliasName) > 256 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'AliasName' failed to satisfy "+
			"constraint: Member must have length less than or equal to 256", *body.AliasName)

		r.logger.WarnContext(r.request.Context(), "validation failed", "aliasName", *body.AliasName)
		return NewValidationExceptionResponse(msg)
	}

	//---

	aliasArn := config.ArnPrefix() + *body.AliasName

	alias, err := r.database.LoadAlias(aliasArn)

	if err != nil {
		msg := fmt.Sprintf("Alias '%s' does not exist", *body.AliasName)

		r.logger.WarnContext(r.request.Context(), "alias not found", "aliasName", *body.AliasName)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	originalKeyArn := config.EnsureArn("key/", alias.TargetKeyId)

	// Lookup the key
	originalKey, _ := r.database.LoadKey(originalKeyArn)

	if originalKey == nil {
		msg := fmt.Sprintf("Original key '%s' does not exist", originalKeyArn)
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", msg)
		return NewInternalFailureExceptionResponse(msg)
	}

	//---

	targetKeyArn := config.EnsureArn("key/", *body.TargetKeyId)

	// Lookup the key
	targetKey, _ := r.database.LoadKey(targetKeyArn)

	if targetKey == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", targetKeyArn)

		r.logger.WarnContext(r.request.Context(), "key not found", "keyArn", targetKeyArn)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	// Key usage cannot change
	if originalKey.GetMetadata().KeyUsage != targetKey.GetMetadata().KeyUsage {
		msg := fmt.Sprintf("Alias %s cannot be changed from a CMK with key usage %s to a CMK with key "+
			"usage %s. The key usage of the current CMK and the new CMK must be the same.",
			*body.AliasName, originalKey.GetMetadata().KeyUsage, targetKey.GetMetadata().KeyUsage)

		r.logger.WarnContext(r.request.Context(), "invalid key usage", "aliasName", *body.AliasName, "originalKeyUsage", originalKey.GetMetadata().KeyUsage, "targetKeyUsage", targetKey.GetMetadata().KeyUsage)
		return NewValidationExceptionResponse(msg)
	}

	// Key type cannot change
	if reflect.TypeOf(originalKey) != reflect.TypeOf(targetKey) {

		// TODO The wording of this validation message needs amending to match AWS.
		msg := fmt.Sprintf("Alias %s cannot be changed from a CMK with key type %s to a CMK with key "+
			"type %s. The key type of the current CMK and the new CMK must be the same.",
			*body.AliasName, reflect.TypeOf(originalKey), reflect.TypeOf(targetKey))

		r.logger.WarnContext(r.request.Context(), "validation failed", "aliasName", *body.AliasName, "originalKeyType", reflect.TypeOf(originalKey).String(), "targetKeyType", reflect.TypeOf(targetKey).String())
		return NewValidationExceptionResponse(msg)
	}

	//---

	if targetKey.GetMetadata().DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", targetKeyArn)

		r.logger.WarnContext(r.request.Context(), "key pending deletion", "keyArn", targetKeyArn)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	alias.TargetKeyId = targetKey.GetMetadata().KeyId
	alias.LastUpdatedDate = float64(time.Now().Unix())

	if err := r.database.SaveAlias(alias); err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.InfoContext(r.request.Context(), "Alias updated", "aliasArn", alias.AliasArn, "keyArn", targetKey.GetArn())

	return NewResponse(200, nil)
}

package handler

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
)

var validAliasName = regexp.MustCompile(`^alias/[a-zA-Z0-9/_-]+$`)

func (r *RequestHandler) CreateAlias() Response {

	var body *kms.CreateAliasInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.CreateAliasInput{}
	}

	//--------------------------------
	// Validation

	if body.TargetKeyId == nil {
		msg := "TargetKeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if body.AliasName == nil {
		msg := "AliasName is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	if !validAliasName.MatchString(*body.AliasName) {
		msg := fmt.Sprintf("The specified alias name %q is not valid. An alias name must begin with 'alias/' "+
			"followed by one or more alphanumeric characters, forward slashes, underscores, or dashes.", *body.AliasName)

		r.logger.Warnf(msg)
		return NewInvalidAliasNameExceptionResponse(msg)
	}

	if strings.HasPrefix(*body.AliasName, "alias/aws/") {
		msg := fmt.Sprintf("The alias namespace \"alias/aws/\" is reserved for AWS managed keys and cannot be used for customer managed keys.")
		r.logger.Warnf(msg)
		return NewNotAuthorizedExceptionResponse(msg)
	}

	if len(*body.AliasName) > 256 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'AliasName' failed to satisfy "+
			"constraint: Member must have length less than or equal to 256", *body.AliasName)

		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	// --------------------------------

	// AWS rejects alias names as TargetKeyId — aliases must refer to keys, not other aliases.
	if strings.HasPrefix(*body.TargetKeyId, "alias/") {
		msg := "Aliases must refer to keys. Not aliases"
		r.logger.Warnf(msg)
		return NewValidationExceptionResponse(msg)
	}

	target := config.EnsureArn("key/", *body.TargetKeyId)

	// Lookup the key
	key, _ := r.database.LoadKey(target)

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", target)

		r.logger.Warnf(msg)
		return NewNotFoundExceptionResponse(msg)
	}

	//---

	if key.GetMetadata().DeletionDate != 0 {
		// Key is pending deletion; cannot create alias
		msg := fmt.Sprintf("%s is pending deletion.", target)

		r.logger.Warnf(msg)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//---

	aliasArn := config.ArnPrefix() + *body.AliasName

	_, err = r.database.LoadAlias(aliasArn)

	if err == nil {
		msg := fmt.Sprintf("An alias with the name %s already exists", aliasArn)

		r.logger.Warnf(msg)
		return NewAlreadyExistsExceptionResponse(msg)
	}

	now := float64(time.Now().Unix())
	alias := &data.Alias{
		AliasName:       *body.AliasName,
		AliasArn:        aliasArn,
		TargetKeyId:     key.GetMetadata().KeyId,
		CreationDate:    now,
		LastUpdatedDate: now,
	}

	if err := r.database.SaveAlias(alias); err != nil {
		r.logger.Error(err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	r.logger.Infof("New alias created: %s -> %s\n", alias.AliasArn, key.GetArn())

	return NewResponse(200, nil)
}

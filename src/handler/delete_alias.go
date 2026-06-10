package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/config"
	"strings"
)

func (r *RequestHandler) DeleteAlias() Response {

	var body *kms.DeleteAliasInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.DeleteAliasInput{}
	}

	//--------------------------------
	// Validation

	if body.AliasName == nil {
		msg := "AliasName is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "field", "AliasName", "error", "required parameter")
		return NewMissingParameterResponse(msg)
	}

	if !strings.HasPrefix(*body.AliasName, "alias/") {
		msg := "Alias must start with the prefix \"alias/\". Please see " +
			"http://docs.aws.amazon.com/kms/latest/developerguide/programming-aliases.html"

		r.logger.WarnContext(r.request.Context(), "validation failed", "field", "AliasName", "error", "missing 'alias/' prefix")
		return NewValidationExceptionResponse(msg)
	}

	if strings.HasPrefix(*body.AliasName, "alias/aws/") {
		msg := fmt.Sprintf("The alias %s is a AWS managed alias and cannot be deleted.", *body.AliasName)
		r.logger.WarnContext(r.request.Context(), "invalid key state", "aliasName", *body.AliasName)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//--------------------------------

	aliasArn := config.ArnPrefix() + *body.AliasName

	_, err = r.database.LoadAlias(aliasArn)

	if err != nil {
		msg := fmt.Sprintf("Alias '%s' does not exist", aliasArn)

		r.logger.WarnContext(r.request.Context(), "alias not found", "aliasArn", aliasArn)
		return NewNotFoundExceptionResponse(msg)
	}

	if err := r.database.DeleteObject(aliasArn); err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.InfoContext(r.request.Context(), "Alias deleted", "aliasArn", aliasArn)

	return NewResponse(200, nil)
}

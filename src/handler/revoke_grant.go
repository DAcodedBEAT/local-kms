package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func (r *RequestHandler) RevokeGrant() Response {
	var body *kms.RevokeGrantInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.RevokeGrantInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "KeyId")
		return NewMissingParameterResponse(msg)
	}

	if body.GrantId == nil {
		msg := "GrantId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "GrantId")
		return NewMissingParameterResponse(msg)
	}

	//---

	key, response := r.getKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	grant, err := r.database.LoadGrant(*body.GrantId)
	if err != nil || grant.KeyArn != key.GetArn() {
		msg := fmt.Sprintf("Grant does not exist: %s", *body.GrantId)

		r.logger.WarnContext(r.request.Context(), "grant not found", "grantId", *body.GrantId, "keyArn", key.GetArn())
		return NewNotFoundExceptionResponse(msg)
	}

	if err := r.database.DeleteGrant(grant.GrantId); err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.InfoContext(r.request.Context(), "Grant revoked", "grantId", grant.GrantId, "keyArn", key.GetArn())

	return NewResponse(200, nil)
}

package handler

import (
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func (r *RequestHandler) RetireGrant() Response {
	var body *kms.RetireGrantInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.RetireGrantInput{}
	}

	//--------------------------------
	// Validation

	hasToken := body.GrantToken != nil && *body.GrantToken != ""
	hasKeyAndGrant := body.KeyId != nil && *body.KeyId != "" && body.GrantId != nil && *body.GrantId != ""

	if !hasToken && !hasKeyAndGrant {
		msg := "Either GrantToken, or both KeyId and GrantId, must be specified"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "GrantToken")
		return NewValidationExceptionResponse(msg)
	}

	//--------------------------------

	if hasToken {
		grant, err := r.database.FindGrantByToken(*body.GrantToken)
		if err != nil {
			r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
			return NewInternalFailureExceptionResponse(err.Error())
		}
		if grant == nil {
			r.logger.WarnContext(r.request.Context(), "grant not found", "grantToken", *body.GrantToken)
			return NewNotFoundExceptionResponse("Grant does not exist for the given grant token")
		}

		if body.GrantId != nil && *body.GrantId != "" && *body.GrantId != grant.GrantId {
			r.logger.WarnContext(r.request.Context(), "grant not found", "grantToken", *body.GrantToken)
			return NewNotFoundExceptionResponse("Grant does not exist for the given grant token")
		}

		if body.KeyId != nil && *body.KeyId != "" {
			key, response := r.getKey(*body.KeyId)
			if !response.Empty() {
				return response
			}
			if key.GetArn() != grant.KeyArn {
				r.logger.WarnContext(r.request.Context(), "grant not found for key", "grantToken", *body.GrantToken, "keyArn", key.GetArn())
				return NewNotFoundExceptionResponse("Grant does not exist for the given key")
			}
		}

		if err := r.database.DeleteGrant(grant.GrantId); err != nil {
			r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
			return NewInternalFailureExceptionResponse(err.Error())
		}

		r.logger.InfoContext(r.request.Context(), "Grant retired", "grantId", grant.GrantId, "keyArn", grant.KeyArn)
		return NewResponse(200, nil)
	}

	//--------------------------------
	// KeyId + GrantId

	key, response := r.getKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	grant, err := r.database.LoadGrant(*body.GrantId)
	if err != nil || grant.KeyArn != key.GetArn() {
		r.logger.WarnContext(r.request.Context(), "grant not found", "grantId", *body.GrantId, "keyArn", key.GetArn())
		return NewNotFoundExceptionResponse("Grant does not exist: " + *body.GrantId)
	}

	if err := r.database.DeleteGrant(grant.GrantId); err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	r.logger.InfoContext(r.request.Context(), "Grant retired", "grantId", grant.GrantId, "keyArn", key.GetArn())
	return NewResponse(200, nil)
}

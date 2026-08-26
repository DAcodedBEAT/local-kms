package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/data"
)

func (r *RequestHandler) ListGrants() Response {
	var body *kms.ListGrantsInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.ListGrantsInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "KeyId")
		return NewMissingParameterResponse(msg)
	}

	var marker string
	var limit int64 = 50

	if body.Marker != nil {
		marker = *body.Marker
	}
	if body.Limit != nil {
		limit = int64(*body.Limit)
	}

	if limit < 1 || limit > 100 {
		msg := fmt.Sprintf("1 validation error detected: Value '%d' at 'limit' failed to satisfy "+
			"constraint: Minimum value of 1. Maximum value of 100.", limit)

		r.logger.WarnContext(r.request.Context(), "validation failed", "limit", limit)
		return NewValidationExceptionResponse(msg)
	}

	//---

	key, response := r.getKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	filter := data.GrantFilter{KeyArn: key.GetArn()}
	if body.GrantId != nil {
		filter.GrantId = *body.GrantId
	}
	if body.GranteePrincipal != nil {
		filter.GranteePrincipal = *body.GranteePrincipal
	}
	if body.GranteeServicePrincipal != nil {
		filter.GranteeServicePrincipal = *body.GranteeServicePrincipal
	}

	//--------------------------------

	// Return 1 extra result to determine if there are > limit
	grants, err := r.database.ListGrants(filter, limit+1, marker)
	if err != nil {
		if _, ok := err.(*data.InvalidMarkerExceptionError); ok {
			r.logger.WarnContext(r.request.Context(), "Invalid marker")
			return New400ExceptionResponse("InvalidMarkerException", "")
		}

		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	response2 := &struct {
		NextMarker string `json:",omitempty"`
		Truncated  bool
		Grants     []*grantListEntry
	}{}

	if int64(len(grants)) > limit {
		response2.Truncated = true
		response2.NextMarker = grants[len(grants)-1].GrantId

		grants = grants[:limit]
	}

	response2.Grants = make([]*grantListEntry, len(grants))
	for i, g := range grants {
		response2.Grants[i] = newGrantListEntry(g)
	}

	//---

	r.logger.DebugContext(r.request.Context(), "Grants listed", "keyArn", key.GetArn(), "count", len(grants), "truncated", response2.Truncated)

	return NewResponse(200, response2)
}

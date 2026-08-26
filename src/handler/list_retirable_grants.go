package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/data"
)

func (r *RequestHandler) ListRetirableGrants() Response {
	var body *kms.ListRetirableGrantsInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.ListRetirableGrantsInput{}
	}

	//--------------------------------
	// Validation

	if body.RetiringPrincipal == nil && body.RetiringServicePrincipal == nil {
		msg := "RetiringPrincipal is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "RetiringPrincipal")
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

	filter := data.GrantFilter{}
	if body.RetiringPrincipal != nil {
		filter.RetiringPrincipal = *body.RetiringPrincipal
	}
	if body.RetiringServicePrincipal != nil {
		filter.RetiringServicePrincipal = *body.RetiringServicePrincipal
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

	response := &struct {
		NextMarker string `json:",omitempty"`
		Truncated  bool
		Grants     []*grantListEntry
	}{}

	if int64(len(grants)) > limit {
		response.Truncated = true
		response.NextMarker = grants[len(grants)-1].GrantId

		grants = grants[:limit]
	}

	response.Grants = make([]*grantListEntry, len(grants))
	for i, g := range grants {
		response.Grants[i] = newGrantListEntry(g)
	}

	//---

	r.logger.DebugContext(r.request.Context(), "Retirable grants listed", "count", len(grants), "truncated", response.Truncated)

	return NewResponse(200, response)
}

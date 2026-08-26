package handler

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/google/uuid"
	"github.com/nsmithuk/local-kms/src/data"
	"github.com/nsmithuk/local-kms/src/service"
)

func (r *RequestHandler) CreateGrant() Response {

	var body *kms.CreateGrantInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.CreateGrantInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "KeyId")
		return NewMissingParameterResponse(msg)
	}

	if len(body.Operations) == 0 {
		msg := "Operations is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "Operations")
		return NewMissingParameterResponse(msg)
	}

	if body.GranteePrincipal == nil && body.GranteeServicePrincipal == nil {
		msg := "Either GranteePrincipal or GranteeServicePrincipal must be specified"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "GranteePrincipal")
		return NewValidationExceptionResponse(msg)
	}

	if body.GranteePrincipal != nil && body.GranteeServicePrincipal != nil {
		msg := "You cannot specify both GranteePrincipal and GranteeServicePrincipal"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "GranteePrincipal")
		return NewValidationExceptionResponse(msg)
	}

	//---

	key, response := r.getKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	if key.GetMetadata().DeletionDate != 0 {
		msg := fmt.Sprintf("%s is pending deletion.", key.GetArn())

		r.logger.WarnContext(r.request.Context(), "key pending deletion", "keyArn", key.GetArn())
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	//--------------------------------

	grantUUID, err := uuid.NewRandom()
	if err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	operations := make([]string, len(body.Operations))
	for i, op := range body.Operations {
		operations[i] = string(op)
	}

	grant := &data.Grant{
		GrantId:      grantUUID.String(),
		GrantToken:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(service.GenerateRandomData(32)),
		KeyArn:       key.GetArn(),
		Operations:   operations,
		CreationDate: float64(time.Now().Unix()),
	}

	if body.Name != nil {
		grant.Name = *body.Name
	}
	if body.GranteePrincipal != nil {
		grant.GranteePrincipal = *body.GranteePrincipal
	}
	if body.GranteeServicePrincipal != nil {
		grant.GranteeServicePrincipal = *body.GranteeServicePrincipal
	}
	if body.RetiringPrincipal != nil {
		grant.RetiringPrincipal = *body.RetiringPrincipal
	}
	if body.RetiringServicePrincipal != nil {
		grant.RetiringServicePrincipal = *body.RetiringServicePrincipal
	}
	if body.Constraints != nil {
		grant.Constraints = &data.GrantConstraints{
			EncryptionContextEquals: body.Constraints.EncryptionContextEquals,
			EncryptionContextSubset: body.Constraints.EncryptionContextSubset,
		}
		if body.Constraints.SourceArn != nil {
			grant.Constraints.SourceArn = *body.Constraints.SourceArn
		}
	}

	if err := r.database.SaveGrant(grant); err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	//---

	r.logger.InfoContext(r.request.Context(), "Grant created", "grantId", grant.GrantId, "keyArn", key.GetArn())

	return NewResponse(200, &struct {
		GrantId    string
		GrantToken string
	}{
		GrantId:    grant.GrantId,
		GrantToken: grant.GrantToken,
	})
}

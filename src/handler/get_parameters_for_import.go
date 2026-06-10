package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/service"
)

type ParametersForImportResponse struct {
	KeyId             string
	ParametersValidTo int64
	ImportToken       string
	PublicKey         string
}

func (r *RequestHandler) GetParametersForImport() Response {

	var body *kms.GetParametersForImportInput
	if err := r.decodeBodyInto(&body); err != nil {
		r.logger.ErrorContext(r.request.Context(), "Failed to decode request", "error", err)
		body = &kms.GetParametersForImportInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "KeyId")
		return NewMissingParameterResponse(msg)
	}

	if body.WrappingAlgorithm == "" {
		msg := "WrappingAlgorithm is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "WrappingAlgorithm")
		return NewMissingParameterResponse(msg)
	}

	var wrappingAlgorithm cmk.WrappingAlgorithm
	switch body.WrappingAlgorithm {
	case "RSAES_PKCS1_V1_5", "RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256":
		wrappingAlgorithm = cmk.WrappingAlgorithm(body.WrappingAlgorithm)

	default:
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'wrappingAlgorithm' failed to satisfy constraint: Member must satisfy enum value set: [RSAES_OAEP_SHA_1, RSAES_OAEP_SHA_256, RSAES_PKCS1_V1_5]", body.WrappingAlgorithm)

		r.logger.WarnContext(r.request.Context(), "validation failed", "wrappingAlgorithm", body.WrappingAlgorithm)
		return NewValidationExceptionResponse(msg)
	}

	if body.WrappingKeySpec == "" {
		msg := "WrappingKeySpec is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "WrappingKeySpec")
		return NewMissingParameterResponse(msg)
	}

	// If wrapping key ever starts accepting additional values then we'll need to adjust this
	var bits = 2048
	if body.WrappingKeySpec != "RSA_2048" {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'wrappingKeySpec' failed to satisfy constraint: Member must satisfy enum value set: [RSA_2048]", body.WrappingKeySpec)

		r.logger.WarnContext(r.request.Context(), "validation failed", "wrappingKeySpec", body.WrappingKeySpec)
		return NewValidationExceptionResponse(msg)
	}

	// //---

	key, response := r.getKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	if key == nil {
		msg := fmt.Sprintf("Key '%s' does not exist", key.GetArn())

		r.logger.WarnContext(r.request.Context(), "key not found", "keyArn", key.GetArn())
		return NewNotFoundExceptionResponse(msg)
	}

	keyMetadata := key.GetMetadata()
	if keyMetadata.Origin != "EXTERNAL" {
		msg := fmt.Sprintf("%s origin is %s which is not valid for this operation.", key.GetArn(), keyMetadata.Origin)

		r.logger.WarnContext(r.request.Context(), "unsupported operation", "keyArn", key.GetArn(), "origin", keyMetadata.Origin)
		return NewUnsupportedOperationException(msg)
	}

	switch keyMetadata.KeyState {
	case cmk.KeyStatePendingDeletion:
		msg := fmt.Sprintf("%s is pending deletion.", *body.KeyId)

		r.logger.WarnContext(r.request.Context(), "key pending deletion", "keyId", *body.KeyId)
		return NewKMSInvalidStateExceptionResponse(msg)

	case cmk.KeyStateUnavailable:
		msg := fmt.Sprintf("%s is unavailable.", *body.KeyId)

		r.logger.WarnContext(r.request.Context(), "invalid key state", "keyId", *body.KeyId)
		return NewKMSInvalidStateExceptionResponse(msg)
	}

	// Create and save the parameters for key material import

	// Starting by generating a wrapping RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		r.logger.ErrorContext(r.request.Context(), "failed to generate RSA key", "error", err)
		return NewResponse(500, err.Error())
	}

	// public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		r.logger.ErrorContext(r.request.Context(), "failed to marshal RSA public key", "error", err)
		return NewResponse(500, err.Error())
	}

	// For import token we just generate a random base64 string that matches the length requirements that would be returned by AWS
	// Parameters are valid for 24 hours as per AWS
	params := &cmk.ParametersForImport{
		ImportToken:       service.GenerateRandomData(256),
		ParametersValidTo: time.Now().Add(24 * time.Duration(time.Hour)).Unix(),
		PrivateKey:        *rsaKey,
		WrappingAlgorithm: wrappingAlgorithm,
	}

	// Note - this is guaranteed to be an AesKey by virtue of the `EXTERNAL` origin
	key.(*cmk.AesKey).SetParametersForImport(params)

	//--------------------------------
	// Save the key

	if err := r.database.SaveKey(key); err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	r.logger.InfoContext(r.request.Context(), "Key import parameters created", "keyArn", key.GetArn())

	return NewResponse(200, &ParametersForImportResponse{
		KeyId:             key.GetArn(),
		ImportToken:       base64.StdEncoding.EncodeToString(params.ImportToken),
		ParametersValidTo: params.ParametersValidTo,
		PublicKey:         base64.StdEncoding.EncodeToString(pubKeyBytes),
	})
}

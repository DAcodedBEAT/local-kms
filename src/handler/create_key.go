package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) CreateKey() Response {

	var body *kms.CreateKeyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.CreateKeyInput{}
	}

	//---

	keyId := uuid.NewString()

	metadata := cmk.KeyMetadata{}
	metadata.Initialize(keyId)

	//--------------------------------
	// Validation

	if body.Description != nil && len(*body.Description) > 8192 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'description' failed to satisfy "+
			"constraint: Member must have length less than or equal to 8192", *body.Description)

		r.logger.WarnContext(r.request.Context(), "validation failed", "value", *body.Description)
		return NewValidationExceptionResponse(msg)
	}

	if body.Policy != nil && len(*body.Policy) > 32768 {
		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'policy' failed to satisfy "+
			"constraint: Member must have length less than or equal to 32768", *body.Policy)

		r.logger.WarnContext(r.request.Context(), "validation failed", "value", *body.Policy)
		return NewValidationExceptionResponse(msg)
	}

	response := r.validateTags(body.Tags)
	if !response.Empty() {
		return response
	}

	if body.Description != nil {
		metadata.Description = *body.Description
	}

	if body.Policy == nil {
		policy := fmt.Sprintf(`{
			"Id": "key-default-policy",
			"Version": "2012-10-17",
			"Statement": [{
				"Sid": "Enable IAM User Permissions",
				"Effect": "Allow",
				"Principal": {
					"AWS": "arn:aws:iam::%s:root"
				},
				"Action": "kms:*",
				"Resource": "*"
			}]
		}`, config.AWSAccountId)
		body.Policy = &policy
	}

	// CustomerMasterKeySpec is deprecated upstream but still accepted by AWS KMS for backwards compatibility.
	// Local KMS preserves that compatibility, so we read the field intentionally.
	//nolint:staticcheck // SA1019: accept deprecated AWS input field for compatibility
	if body.KeySpec != "" && body.CustomerMasterKeySpec != "" {
		// Both values cannot be set

		msg := "You cannot specify KeySpec and CustomerMasterKeySpec in the same request. CustomerMasterKeySpec is deprecated."
		r.logger.WarnContext(r.request.Context(), "validation failed", "error", "both KeySpec and CustomerMasterKeySpec specified")
		return NewValidationExceptionResponse(msg)
		//nolint:staticcheck // SA1019: accept deprecated AWS input field for compatibility
	} else if body.KeySpec == "" && body.CustomerMasterKeySpec != "" {
		// If we only have CustomerMasterKeySpec, copy it over to KeySpec
		//nolint:staticcheck // SA1019: accept deprecated AWS input field for compatibility
		body.KeySpec = kmstypes.KeySpec(body.CustomerMasterKeySpec)

	} else if body.KeySpec == "" {
		// Neither set; default is SYMMETRIC_DEFAULT
		body.KeySpec = kmstypes.KeySpec(cmk.SpecSymmetricDefault)
	}

	if body.Origin != "" {
		switch cmk.KeyOrigin(body.Origin) {
		case cmk.KeyOriginAwsKms:
			// nop
		case cmk.KeyOriginExternal:

			if cmk.KeySpec(body.KeySpec) != cmk.SpecSymmetricDefault {
				msg := fmt.Sprintf("KeySpec %s is not supported for Origin %s", body.KeySpec, body.Origin)

				r.logger.WarnContext(r.request.Context(), "validation failed", "keySpec", body.KeySpec, "origin", body.Origin)
				return NewValidationExceptionResponse(msg)
			}

			r.logger.DebugContext(r.request.Context(), "Key origin set", "origin", body.Origin, "state", "PendingImport")
			metadata.Origin = cmk.KeyOriginExternal
			metadata.Enabled = false
			metadata.KeyState = cmk.KeyStatePendingImport

		case cmk.KeyOriginAwsCloudHsm:

			msg := "Local KMS does not yet support Origin AWS_CLOUDHSM."
			r.logger.WarnContext(r.request.Context(), "unsupported operation", "origin", body.Origin)
			return NewUnsupportedOperationException(msg)

		default:

			msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'origin' failed to satisfy constraint: Member must satisfy enum value set: [EXTERNAL, AWS_CLOUDHSM, AWS_KMS]", body.Origin)

			r.logger.WarnContext(r.request.Context(), "validation failed", "origin", body.Origin)
			return NewValidationExceptionResponse(msg)
		}
	}

	//---

	var key cmk.Key

	switch cmk.KeySpec(body.KeySpec) {
	case cmk.SpecSymmetricDefault:

		if body.KeyUsage != "" && cmk.KeyUsage(body.KeyUsage) != cmk.UsageEncryptDecrypt {
			msg := fmt.Sprintf("The operation failed because the KeyUsage value of the CMK is %s. To perform this operation, the KeyUsage value must be ENCRYPT_DECRYPT.", body.KeyUsage)
			r.logger.WarnContext(r.request.Context(), "invalid key usage", "keyUsage", body.KeyUsage)
			return NewValidationExceptionResponse(msg)
		}

		key = cmk.NewAesKey(metadata, *body.Policy, metadata.Origin)

	case cmk.SpecEccNistP256, cmk.SpecEccNistP384, cmk.SpecEccNistP521, cmk.SpecEccSecp256k1:

		if body.KeyUsage == "" {
			msg := "You must specify a KeyUsage value for an asymmetric CMK."
			r.logger.WarnContext(r.request.Context(), "validation failed", "field", "KeyUsage", "error", "required for asymmetric CMK")
			return NewValidationExceptionResponse(msg)
		}

		if cmk.KeyUsage(body.KeyUsage) != cmk.UsageSignVerify {
			msg := fmt.Sprintf("KeyUsage ENCRYPT_DECRYPT is not compatible with KeySpec %s", body.KeySpec)
			r.logger.WarnContext(r.request.Context(), "invalid key usage", "keySpec", body.KeySpec, "keyUsage", body.KeyUsage)
			return NewValidationExceptionResponse(msg)
		}

		key, err = cmk.NewEccKey(cmk.KeySpec(body.KeySpec), metadata, *body.Policy)
		if err != nil {
			r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
			return NewInternalFailureExceptionResponse(err.Error())
		}

	case cmk.SpecRsa2048, cmk.SpecRsa3072, cmk.SpecRsa4096:

		if body.KeyUsage == "" {
			msg := "You must specify a KeyUsage value for an asymmetric CMK."
			r.logger.WarnContext(r.request.Context(), "validation failed", "field", "KeyUsage", "error", "required for asymmetric CMK")
			return NewValidationExceptionResponse(msg)
		}

		usage := cmk.KeyUsage(body.KeyUsage)
		if usage != cmk.UsageSignVerify && usage != cmk.UsageEncryptDecrypt {
			msg := fmt.Sprintf("KeyUsage %s is not compatible with KeySpec %s", body.KeyUsage, body.KeySpec)
			r.logger.WarnContext(r.request.Context(), "invalid key usage", "keyUsage", body.KeyUsage, "keySpec", body.KeySpec)
			return NewValidationExceptionResponse(msg)
		}

		key, err = cmk.NewRsaKey(cmk.KeySpec(body.KeySpec), cmk.KeyUsage(body.KeyUsage), metadata, *body.Policy)
		if err != nil {
			r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
			return NewInternalFailureExceptionResponse(err.Error())
		}

	case "HMAC_224", "HMAC_256", "HMAC_384", "HMAC_512":

		if body.KeyUsage == "" {
			msg := "You must specify a KeyUsage value for an HMAC CMK."
			r.logger.WarnContext(r.request.Context(), "missing key usage for HMAC", "keySpec", body.KeySpec)
			return NewValidationExceptionResponse(msg)
		}

		if cmk.KeyUsage(body.KeyUsage) != cmk.UsageGenerateVerifyMac {
			msg := fmt.Sprintf("KeyUsage %s is not compatible with KeySpec %s", body.KeyUsage, body.KeySpec)
			r.logger.WarnContext(r.request.Context(), "invalid key usage", "keyUsage", body.KeyUsage, "keySpec", body.KeySpec)
			return NewValidationExceptionResponse(msg)
		}

		key, err = cmk.NewHmacKey(cmk.KeySpec(body.KeySpec), metadata, *body.Policy, metadata.Origin)
		if err != nil {
			r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
			return NewInternalFailureExceptionResponse(err.Error())
		}

	default:

		msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'KeySpec' "+
			"failed to satisfy constraint: Member must satisfy enum value set: [RSA_2048, ECC_NIST_P384, "+
			"ECC_NIST_P256, ECC_NIST_P521, RSA_3072, ECC_SECG_P256K1, RSA_4096, SYMMETRIC_DEFAULT, "+
			"HMAC_224, HMAC_256, HMAC_384, HMAC_512]", body.KeySpec)

		r.logger.WarnContext(r.request.Context(), "invalid key spec", "keySpec", body.KeySpec)

		return NewValidationExceptionResponse(msg)
	}

	//--------------------------------
	// Save the key

	err = r.database.SaveKey(key)
	if err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	r.logger.InfoContext(r.request.Context(), "Key created", "keySpec", key.GetMetadata().KeySpec, "keyArn", key.GetArn())

	//--------------------------------
	// Create the tags

	response = r.saveTags(key, body.Tags)
	if !response.Empty() {
		return response
	}

	//---

	return NewResponse(200, map[string]*cmk.KeyMetadata{
		"KeyMetadata": key.GetMetadata(),
	})
}

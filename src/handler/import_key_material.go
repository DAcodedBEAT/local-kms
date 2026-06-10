package handler

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/nsmithuk/local-kms/src/cmk"
)

// Using custom struct to be able to decode ValidTo
// as simple Int64. Alternative would be custom
// type and marshal/unmarshal functions (again not
// possible using the type from the AWS library)
type ImportKeyMaterialInput struct {
	KeyId                *string
	ImportToken          []byte
	EncryptedKeyMaterial []byte
	ExpirationModel      *string
	// We override this from
	// ValidTo *time.Time `type:"timestamp"`
	// as json.Decode doesn't like epochs
	ValidTo *int64
}

func (r *RequestHandler) ImportKeyMaterial() Response {
	var body *ImportKeyMaterialInput
	if err := r.decodeBodyInto(&body); err != nil {
		r.logger.ErrorContext(r.request.Context(), "Failed to decode request", "error", err)
		body = &ImportKeyMaterialInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), msg)
		return NewMissingParameterResponse(msg)
	}

	if body.ImportToken == nil {
		msg := "ImportToken is a required parameter"

		r.logger.WarnContext(r.request.Context(), msg)
		return NewMissingParameterResponse(msg)
	}

	if body.EncryptedKeyMaterial == nil {
		msg := "EncryptedKeyMaterial is a required parameter"

		r.logger.WarnContext(r.request.Context(), msg)
		return NewMissingParameterResponse(msg)
	}

	var expirationModel cmk.ExpirationModel
	if body.ExpirationModel == nil {
		if body.ValidTo != nil {
			expirationModel = cmk.ExpirationModelKeyMaterialExpires
		} else {
			expirationModel = cmk.ExpirationModelKeyMaterialDoesNotExpire
		}
	} else {
		switch *body.ExpirationModel {
		case "KEY_MATERIAL_EXPIRES", "KEY_MATERIAL_DOES_NOT_EXPIRE":
			expirationModel = cmk.ExpirationModel(*body.ExpirationModel)
		default:
			msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'expirationModel' failed to satisfy constraint: Member must satisfy enum value set: [KEY_MATERIAL_DOES_NOT_EXPIRE, KEY_MATERIAL_EXPIRES]", *body.ExpirationModel)
			r.logger.WarnContext(r.request.Context(), "validation failed", "value", *body.ExpirationModel)
			return NewValidationExceptionResponse(msg)
		}
	}

	if expirationModel == cmk.ExpirationModelKeyMaterialExpires && body.ValidTo == nil {
		msg := "A validTo date must be set if the ExpirationModel is KEY_MATERIAL_EXPIRES"
		r.logger.WarnContext(r.request.Context(), msg)
		return NewValidationExceptionResponse(msg)
	}

	if expirationModel == cmk.ExpirationModelKeyMaterialDoesNotExpire && body.ValidTo != nil {
		msg := "The parameter ValidTo cannot be specified for a key with an expiration model of KEY_MATERIAL_DOES_NOT_EXPIRE"
		r.logger.WarnContext(r.request.Context(), msg)
		return NewValidationExceptionResponse(msg)
	}

	// TODO: AWS does actually check the size of the encrypted data to ensure it matches the wrapping algorithm
	// An error occurred (ValidationException) when calling the ImportKeyMaterial operation: Invalid encrypted key size.

	if body.ValidTo != nil && *body.ValidTo <= time.Now().Unix() {
		msg := "ValidTo must be in the future"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "ValidTo")
		return NewValidationExceptionResponse(msg)
	}

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
	if keyMetadata.Origin != cmk.KeyOriginExternal {
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

	params := key.(*cmk.AesKey).GetParametersForImport()
	if params == nil || !bytes.Equal(params.ImportToken, body.ImportToken) {

		r.logger.WarnContext(r.request.Context(), "Invalid import token", "keyArn", key.GetArn())
		return NewInvalidImportTokenExceptionResponse()
	}

	if params.ParametersValidTo < time.Now().Unix() {
		r.logger.WarnContext(r.request.Context(), "import token expired", "keyArn", key.GetArn())
		return NewExpiredImportTokenExceptionResponse()
	}

	// Attempt to decrypt the encyrpted key material
	var decrypterOps crypto.DecrypterOpts
	switch params.WrappingAlgorithm {
	case cmk.WrappingAlgorithmOaepSha1:
		decrypterOps = &rsa.OAEPOptions{Hash: crypto.SHA1}
	case cmk.WrappingAlgorithmOaepSh256:
		decrypterOps = &rsa.OAEPOptions{Hash: crypto.SHA256}
	case cmk.WrappingAlgorithmPkcs1V15:
		decrypterOps = &rsa.PKCS1v15DecryptOptions{}
	}

	keyMaterial, err := params.PrivateKey.Decrypt(rand.Reader, body.EncryptedKeyMaterial, decrypterOps)
	if err != nil {
		r.logger.WarnContext(r.request.Context(), "unable to decode EncryptedKeyMaterial", "error", err)
		return NewInvalidCiphertextExceptionResponse("")
	}

	if err = key.(*cmk.AesKey).ImportKeyMaterial(keyMaterial); err != nil {
		r.logger.WarnContext(r.request.Context(), "unable to import key material", "error", err)
		return NewIncorrectKeyMaterialExceptionResponse()
	}

	keyMetadata.ExpirationModel = expirationModel
	keyMetadata.KeyState = cmk.KeyStateEnabled
	keyMetadata.Enabled = true

	if expirationModel == cmk.ExpirationModelKeyMaterialExpires {
		keyMetadata.ValidTo = float64(*body.ValidTo)
	} else {
		keyMetadata.ValidTo = 0
	}

	//--------------------------------
	// Save the key

	if err = r.database.SaveKey(key); err != nil {
		r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
		return NewInternalFailureExceptionResponse(err.Error())
	}

	r.logger.InfoContext(r.request.Context(), "Key material imported", "keyArn", key.GetArn())

	return NewResponse(200, &struct {
		KeyId string
	}{
		KeyId: key.GetArn(),
	})
}

package handler

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/service"
)

type GenerateDataKeyResponse struct {
	KeyId          string
	Plaintext      []byte `json:",omitempty"`
	CiphertextBlob []byte
}

//----------------------------------

func (r *RequestHandler) GenerateDataKey() Response {

	errResponse, keyResponse := r.generateDataKey()

	if !errResponse.Empty() {
		return errResponse
	}

	//---

	r.logger.InfoContext(r.request.Context(), "Data key generated with plaintext", "keyArn", keyResponse.KeyId)

	return NewResponse(200, keyResponse)
}

//------------------------------------------------------------------------------------------
// Generate code shared between GenerateDataKey() and GenerateDataKeyWithoutPlaintext()

func (r *RequestHandler) generateDataKey() (Response, *GenerateDataKeyResponse) {

	var body *kms.GenerateDataKeyInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.GenerateDataKeyInput{}
	}

	var bytesRequired uint16

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.WarnContext(r.request.Context(), "validation failed", "parameter", "KeyId")
		return NewMissingParameterResponse(msg), nil
	}

	if body.NumberOfBytes == nil && body.KeySpec == "" {
		msg := "1 validation error detected: Either KeySpec or NumberOfBytes is required."

		r.logger.WarnContext(r.request.Context(), "validation failed", "reason", "missing required parameter")
		return NewValidationExceptionResponse(msg), nil
	}

	if body.NumberOfBytes != nil && body.KeySpec != "" {
		msg := "1 validation error detected: Both KeySpec and NumberOfBytes cannot be provided."

		r.logger.WarnContext(r.request.Context(), "validation failed", "reason", "multiple parameters provided")
		return NewValidationExceptionResponse(msg), nil
	}

	if body.NumberOfBytes != nil && (*body.NumberOfBytes < 1 || *body.NumberOfBytes > 1024) {
		msg := fmt.Sprintf("1 validation error detected: Value '%d' at 'NumberOfBytes' failed to satisfy "+
			"constraint: Member must have minimum value of 1 and maximum value of 1024.", *body.NumberOfBytes)

		r.logger.WarnContext(r.request.Context(), "validation failed", "bytes", *body.NumberOfBytes)
		return NewValidationExceptionResponse(msg), nil
	}

	if body.KeySpec != "" {
		switch body.KeySpec {
		case "AES_128":
			bytesRequired = 128 / 8

		case "AES_256":
			bytesRequired = 256 / 8

		default:
			msg := fmt.Sprintf("1 validation error detected: Value '%s' at 'KeySpec' failed to satisfy "+
				"constraint: Member must be AES_128 or AES_256", body.KeySpec)

			r.logger.WarnContext(r.request.Context(), "invalid key spec", "keySpec", body.KeySpec)
			return NewValidationExceptionResponse(msg), nil
		}

	} else {
		// #nosec G115 -- NumberOfBytes validated above to be in [1, 1024], fits uint16.
		bytesRequired = uint16(*body.NumberOfBytes)
	}

	//----------------------------------

	key, response := r.getUsableKey(*body.KeyId)

	// If the response is not empty, there was an error
	if !response.Empty() {
		return response, nil
	}

	//----------------------------------

	plaintext := service.GenerateRandomData(bytesRequired)

	var cipherResponse []byte

	switch k := key.(type) {
	case *cmk.AesKey:

		cipherResponse, err = k.EncryptAndPackage(plaintext, body.EncryptionContext)
		if err != nil {
			r.logger.ErrorContext(r.request.Context(), "internal error", "error", err)
			return NewInternalFailureExceptionResponse(err.Error()), nil
		}

	default:

		if k.GetMetadata().KeyUsage == cmk.UsageSignVerify {
			msg := fmt.Sprintf("%s key usage is SIGN_VERIFY which is not valid for GenerateDataKey.", k.GetArn())

			r.logger.WarnContext(r.request.Context(), "invalid key usage", "keyArn", k.GetArn(), "keyUsage", k.GetMetadata().KeyUsage)
			return NewInvalidKeyUsageException(msg), nil
		}

		msg := fmt.Sprintf("%s key KeySpec is %s which is not valid for GenerateDataKey.", k.GetArn(), k.GetMetadata().CustomerMasterKeySpec)
		r.logger.WarnContext(r.request.Context(), "invalid key spec", "keyArn", k.GetArn(), "keySpec", k.GetMetadata().CustomerMasterKeySpec)
		return NewInvalidKeyUsageException(msg), nil
	}

	return Response{}, &GenerateDataKeyResponse{
		KeyId:          key.GetArn(),
		Plaintext:      plaintext,
		CiphertextBlob: cipherResponse,
	}
}

package handler

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nsmithuk/local-kms/src/cmk"
	"github.com/nsmithuk/local-kms/src/config"
)

func (r *RequestHandler) GetKeyRotationStatus() Response {

	var body *kms.GetKeyRotationStatusInput
	err := r.decodeBodyInto(&body)

	if err != nil {
		body = &kms.GetKeyRotationStatusInput{}
	}

	//--------------------------------
	// Validation

	if body.KeyId == nil {
		msg := "KeyId is a required parameter"

		r.logger.Warnf(msg)
		return NewMissingParameterResponse(msg)
	}

	//---

	key, response := r.getKey(*body.KeyId)
	if !response.Empty() {
		return response
	}

	//---

	// Only symmetric AWS_KMS keys support rotation
	if key.GetMetadata().Origin == cmk.KeyOriginExternal {
		msg := fmt.Sprintf("%s origin is EXTERNAL which is not valid for this operation.", key.GetArn())
		r.logger.Warnf(msg)
		return NewUnsupportedOperationException(msg)
	}

	aesKey, ok := key.(*cmk.AesKey)
	if !ok {
		msg := fmt.Sprintf("Key '%s' does not support rotation", config.EnsureArn("key/", *body.KeyId))
		r.logger.Warnf(msg)
		return NewUnsupportedOperationException(msg)
	}

	//---

	r.logger.Infof("Key rotation status returned: %s\n", key.GetArn())

	rotationEnabled := !aesKey.NextKeyRotation.IsZero()

	resp := map[string]interface{}{
		"KeyId":               key.GetArn(),
		"KeyRotationEnabled":  rotationEnabled,
		"RotationPeriodInDays": 365,
	}

	if rotationEnabled {
		resp["NextRotationDate"] = float64(aesKey.NextKeyRotation.Unix())
	}

	return NewResponse(200, resp)
}

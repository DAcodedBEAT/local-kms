package handler

func (r *RequestHandler) GenerateDataKeyPairWithoutPlaintext() Response {
	errResponse, keyResponse := r.generateDataKeyPair()

	if !errResponse.Empty() {
		return errResponse
	}

	// Strip out the Plaintext
	keyResponse.PrivateKeyPlaintext = nil

	//---

	r.logger.InfoContext(r.request.Context(), "Data key pair generated without plaintext", "keyArn", keyResponse.KeyId)

	return NewResponse(200, keyResponse)
}

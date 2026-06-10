package handler

func (r *RequestHandler) GenerateDataKeyWithoutPlaintext() Response {
	errResponse, keyResponse := r.generateDataKey()

	if !errResponse.Empty() {
		return errResponse
	}

	// Strip out the Plaintext
	keyResponse.Plaintext = nil

	//---

	r.logger.InfoContext(r.request.Context(), "Data key generated without plaintext", "keyArn", keyResponse.KeyId)

	return NewResponse(200, keyResponse)
}

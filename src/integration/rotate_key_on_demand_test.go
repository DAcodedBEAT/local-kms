package integration

import (
	"testing"
)

func TestRotateKeyOnDemand_NonExistentKey(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	keyId := "arn:aws:kms:us-east-1:111122223333:key/00000000-1111-2222-3333-444444444444"
	resp, data := makeKMSRequest(t, server, "RotateKeyOnDemand", map[string]interface{}{
		"KeyId": keyId,
	})

	if resp.StatusCode != 400 {
		t.Errorf("Expected status code 400, got %d", resp.StatusCode)
	}

	if errorType := data["__type"]; errorType != "NotFoundException" {
		t.Errorf("Expected error type 'NotFoundException', got '%v'", errorType)
	}
}

func TestRotateKeyOnDemand_Success(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	createResp, createData := makeKMSRequest(t, server, "CreateKey", nil)
	if createResp.StatusCode != 200 {
		t.Fatalf("Failed to create key: status %d, data: %+v", createResp.StatusCode, createData)
	}

	keyMetadata := createData["KeyMetadata"].(map[string]interface{})
	keyId := keyMetadata["KeyId"].(string)
	keyArn := keyMetadata["Arn"].(string)

	rotateResp, rotateData := makeKMSRequest(t, server, "RotateKeyOnDemand", map[string]interface{}{
		"KeyId": keyId,
	})

	if rotateResp.StatusCode != 200 {
		t.Fatalf("Expected status code 200, got %d. Response: %+v", rotateResp.StatusCode, rotateData)
	}

	if rotatedKeyId := rotateData["KeyId"]; rotatedKeyId != keyArn {
		t.Errorf("Expected KeyId '%s', got '%v'", keyArn, rotatedKeyId)
	}

	// A key encrypted after rotation should still round-trip through decrypt.
	encryptResp, encryptData := makeKMSRequest(t, server, "Encrypt", map[string]interface{}{
		"KeyId":     keyId,
		"Plaintext": "aGVsbG8=", // "hello"
	})
	if encryptResp.StatusCode != 200 {
		t.Fatalf("Failed to encrypt: status %d, data: %+v", encryptResp.StatusCode, encryptData)
	}

	decryptResp, decryptData := makeKMSRequest(t, server, "Decrypt", map[string]interface{}{
		"CiphertextBlob": encryptData["CiphertextBlob"],
	})
	if decryptResp.StatusCode != 200 {
		t.Fatalf("Failed to decrypt: status %d, data: %+v", decryptResp.StatusCode, decryptData)
	}
	if plaintext := decryptData["Plaintext"]; plaintext != "aGVsbG8=" {
		t.Errorf("Expected round-tripped plaintext 'aGVsbG8=', got '%v'", plaintext)
	}
}

func TestRotateKeyOnDemand_AsymmetricKeyUnsupported(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	createResp, createData := makeKMSRequest(t, server, "CreateKey", map[string]interface{}{
		"KeyUsage": "SIGN_VERIFY",
		"KeySpec":  "RSA_2048",
	})
	if createResp.StatusCode != 200 {
		t.Fatalf("Failed to create key: status %d, data: %+v", createResp.StatusCode, createData)
	}

	keyMetadata := createData["KeyMetadata"].(map[string]interface{})
	keyId := keyMetadata["KeyId"].(string)

	rotateResp, rotateData := makeKMSRequest(t, server, "RotateKeyOnDemand", map[string]interface{}{
		"KeyId": keyId,
	})

	if rotateResp.StatusCode != 400 {
		t.Errorf("Expected status code 400, got %d", rotateResp.StatusCode)
	}
	if errorType := rotateData["__type"]; errorType != "UnsupportedOperationException" {
		t.Errorf("Expected error type 'UnsupportedOperationException', got '%v'", errorType)
	}
}

func TestRotateKeyOnDemand_QuotaExceeded(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	createResp, createData := makeKMSRequest(t, server, "CreateKey", nil)
	if createResp.StatusCode != 200 {
		t.Fatalf("Failed to create key: status %d, data: %+v", createResp.StatusCode, createData)
	}

	keyMetadata := createData["KeyMetadata"].(map[string]interface{})
	keyId := keyMetadata["KeyId"].(string)

	for i := 0; i < 25; i++ {
		resp, data := makeKMSRequest(t, server, "RotateKeyOnDemand", map[string]interface{}{
			"KeyId": keyId,
		})
		if resp.StatusCode != 200 {
			t.Fatalf("Rotation %d: expected status code 200, got %d, data: %+v", i+1, resp.StatusCode, data)
		}
	}

	resp, data := makeKMSRequest(t, server, "RotateKeyOnDemand", map[string]interface{}{
		"KeyId": keyId,
	})
	if resp.StatusCode != 400 {
		t.Fatalf("Expected status code 400 on 26th rotation, got %d", resp.StatusCode)
	}
	if errorType := data["__type"]; errorType != "LimitExceededException" {
		t.Errorf("Expected error type 'LimitExceededException', got '%v'", errorType)
	}
}

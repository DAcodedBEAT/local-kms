package integration

import (
	"testing"
)

func TestCreateGrant_Success(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	createResp, createData := makeKMSRequest(t, server, "CreateKey", nil)
	if createResp.StatusCode != 200 {
		t.Fatalf("Failed to create key: status %d, data: %+v", createResp.StatusCode, createData)
	}
	keyId := createData["KeyMetadata"].(map[string]interface{})["KeyId"].(string)

	resp, data := makeKMSRequest(t, server, "CreateGrant", map[string]interface{}{
		"KeyId":            keyId,
		"GranteePrincipal": "arn:aws:iam::111122223333:role/example-role",
		"Operations":       []string{"Encrypt", "Decrypt"},
	})

	if resp.StatusCode != 200 {
		t.Fatalf("Expected status code 200, got %d, data: %+v", resp.StatusCode, data)
	}
	if data["GrantId"] == nil || data["GrantId"] == "" {
		t.Errorf("Expected non-empty GrantId, got %+v", data["GrantId"])
	}
	if data["GrantToken"] == nil || data["GrantToken"] == "" {
		t.Errorf("Expected non-empty GrantToken, got %+v", data["GrantToken"])
	}
}

func TestCreateGrant_MissingOperations(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	createResp, createData := makeKMSRequest(t, server, "CreateKey", nil)
	if createResp.StatusCode != 200 {
		t.Fatalf("Failed to create key: status %d", createResp.StatusCode)
	}
	keyId := createData["KeyMetadata"].(map[string]interface{})["KeyId"].(string)

	resp, data := makeKMSRequest(t, server, "CreateGrant", map[string]interface{}{
		"KeyId":            keyId,
		"GranteePrincipal": "arn:aws:iam::111122223333:role/example-role",
	})

	if resp.StatusCode != 400 {
		t.Errorf("Expected status code 400, got %d", resp.StatusCode)
	}
	if errorType := data["__type"]; errorType != "MissingParameterException" {
		t.Errorf("Expected error type 'MissingParameterException', got '%v'", errorType)
	}
}

func TestCreateGrant_NonExistentKey(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	resp, data := makeKMSRequest(t, server, "CreateGrant", map[string]interface{}{
		"KeyId":            "arn:aws:kms:us-east-1:111122223333:key/00000000-1111-2222-3333-444444444444",
		"GranteePrincipal": "arn:aws:iam::111122223333:role/example-role",
		"Operations":       []string{"Encrypt"},
	})

	if resp.StatusCode != 400 {
		t.Errorf("Expected status code 400, got %d", resp.StatusCode)
	}
	if errorType := data["__type"]; errorType != "NotFoundException" {
		t.Errorf("Expected error type 'NotFoundException', got '%v'", errorType)
	}
}

func TestListGrants_ReturnsCreatedGrant(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	createResp, createData := makeKMSRequest(t, server, "CreateKey", nil)
	if createResp.StatusCode != 200 {
		t.Fatalf("Failed to create key: status %d", createResp.StatusCode)
	}
	keyId := createData["KeyMetadata"].(map[string]interface{})["KeyId"].(string)
	keyArn := createData["KeyMetadata"].(map[string]interface{})["Arn"].(string)

	grantResp, grantData := makeKMSRequest(t, server, "CreateGrant", map[string]interface{}{
		"KeyId":            keyId,
		"GranteePrincipal": "arn:aws:iam::111122223333:role/example-role",
		"Operations":       []string{"Encrypt", "Decrypt"},
	})
	if grantResp.StatusCode != 200 {
		t.Fatalf("Failed to create grant: status %d, data: %+v", grantResp.StatusCode, grantData)
	}
	grantId := grantData["GrantId"].(string)

	listResp, listData := makeKMSRequest(t, server, "ListGrants", map[string]interface{}{
		"KeyId": keyId,
	})
	if listResp.StatusCode != 200 {
		t.Fatalf("Expected status code 200, got %d, data: %+v", listResp.StatusCode, listData)
	}

	grants, ok := listData["Grants"].([]interface{})
	if !ok || len(grants) != 1 {
		t.Fatalf("Expected 1 grant, got: %+v", listData["Grants"])
	}

	entry := grants[0].(map[string]interface{})
	if entry["GrantId"] != grantId {
		t.Errorf("Expected GrantId '%s', got '%v'", grantId, entry["GrantId"])
	}
	if entry["KeyId"] != keyArn {
		t.Errorf("Expected KeyId '%s', got '%v'", keyArn, entry["KeyId"])
	}
}

func TestRevokeGrant_RemovesGrant(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	createResp, createData := makeKMSRequest(t, server, "CreateKey", nil)
	if createResp.StatusCode != 200 {
		t.Fatalf("Failed to create key: status %d", createResp.StatusCode)
	}
	keyId := createData["KeyMetadata"].(map[string]interface{})["KeyId"].(string)

	grantResp, grantData := makeKMSRequest(t, server, "CreateGrant", map[string]interface{}{
		"KeyId":            keyId,
		"GranteePrincipal": "arn:aws:iam::111122223333:role/example-role",
		"Operations":       []string{"Encrypt"},
	})
	if grantResp.StatusCode != 200 {
		t.Fatalf("Failed to create grant: status %d", grantResp.StatusCode)
	}
	grantId := grantData["GrantId"].(string)

	revokeResp, revokeData := makeKMSRequest(t, server, "RevokeGrant", map[string]interface{}{
		"KeyId":   keyId,
		"GrantId": grantId,
	})
	if revokeResp.StatusCode != 200 {
		t.Fatalf("Expected status code 200, got %d, data: %+v", revokeResp.StatusCode, revokeData)
	}

	listResp, listData := makeKMSRequest(t, server, "ListGrants", map[string]interface{}{
		"KeyId": keyId,
	})
	if listResp.StatusCode != 200 {
		t.Fatalf("Expected status code 200, got %d", listResp.StatusCode)
	}
	if grants, ok := listData["Grants"].([]interface{}); ok && len(grants) != 0 {
		t.Errorf("Expected 0 grants after revoke, got %d", len(grants))
	}

	// Revoking again should fail with NotFoundException.
	resp, data := makeKMSRequest(t, server, "RevokeGrant", map[string]interface{}{
		"KeyId":   keyId,
		"GrantId": grantId,
	})
	if resp.StatusCode != 400 {
		t.Errorf("Expected status code 400, got %d", resp.StatusCode)
	}
	if errorType := data["__type"]; errorType != "NotFoundException" {
		t.Errorf("Expected error type 'NotFoundException', got '%v'", errorType)
	}
}

func TestRetireGrant_ByToken(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	createResp, createData := makeKMSRequest(t, server, "CreateKey", nil)
	if createResp.StatusCode != 200 {
		t.Fatalf("Failed to create key: status %d", createResp.StatusCode)
	}
	keyId := createData["KeyMetadata"].(map[string]interface{})["KeyId"].(string)

	grantResp, grantData := makeKMSRequest(t, server, "CreateGrant", map[string]interface{}{
		"KeyId":             keyId,
		"GranteePrincipal":  "arn:aws:iam::111122223333:role/example-role",
		"RetiringPrincipal": "arn:aws:iam::111122223333:role/example-retiree",
		"Operations":        []string{"Encrypt"},
	})
	if grantResp.StatusCode != 200 {
		t.Fatalf("Failed to create grant: status %d", grantResp.StatusCode)
	}
	grantToken := grantData["GrantToken"].(string)

	retireResp, retireData := makeKMSRequest(t, server, "RetireGrant", map[string]interface{}{
		"GrantToken": grantToken,
	})
	if retireResp.StatusCode != 200 {
		t.Fatalf("Expected status code 200, got %d, data: %+v", retireResp.StatusCode, retireData)
	}

	listResp, listData := makeKMSRequest(t, server, "ListGrants", map[string]interface{}{
		"KeyId": keyId,
	})
	if listResp.StatusCode != 200 {
		t.Fatalf("Expected status code 200, got %d", listResp.StatusCode)
	}
	if grants, ok := listData["Grants"].([]interface{}); ok && len(grants) != 0 {
		t.Errorf("Expected 0 grants after retire, got %d", len(grants))
	}
}

func TestListRetirableGrants_FiltersByRetiringPrincipal(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	createResp, createData := makeKMSRequest(t, server, "CreateKey", nil)
	if createResp.StatusCode != 200 {
		t.Fatalf("Failed to create key: status %d", createResp.StatusCode)
	}
	keyId := createData["KeyMetadata"].(map[string]interface{})["KeyId"].(string)

	retiree := "arn:aws:iam::111122223333:role/example-retiree"

	grantResp, grantData := makeKMSRequest(t, server, "CreateGrant", map[string]interface{}{
		"KeyId":             keyId,
		"GranteePrincipal":  "arn:aws:iam::111122223333:role/example-role",
		"RetiringPrincipal": retiree,
		"Operations":        []string{"Encrypt"},
	})
	if grantResp.StatusCode != 200 {
		t.Fatalf("Failed to create grant: status %d", grantResp.StatusCode)
	}
	grantId := grantData["GrantId"].(string)

	// A second grant with a different retiring principal should not show up.
	otherResp, otherData := makeKMSRequest(t, server, "CreateGrant", map[string]interface{}{
		"KeyId":             keyId,
		"GranteePrincipal":  "arn:aws:iam::111122223333:role/other-role",
		"RetiringPrincipal": "arn:aws:iam::111122223333:role/someone-else",
		"Operations":        []string{"Decrypt"},
	})
	if otherResp.StatusCode != 200 {
		t.Fatalf("Failed to create second grant: status %d, data: %+v", otherResp.StatusCode, otherData)
	}

	listResp, listData := makeKMSRequest(t, server, "ListRetirableGrants", map[string]interface{}{
		"RetiringPrincipal": retiree,
	})
	if listResp.StatusCode != 200 {
		t.Fatalf("Expected status code 200, got %d, data: %+v", listResp.StatusCode, listData)
	}

	grants, ok := listData["Grants"].([]interface{})
	if !ok || len(grants) != 1 {
		t.Fatalf("Expected 1 retirable grant, got: %+v", listData["Grants"])
	}
	if grants[0].(map[string]interface{})["GrantId"] != grantId {
		t.Errorf("Expected GrantId '%s', got '%v'", grantId, grants[0].(map[string]interface{})["GrantId"])
	}
}

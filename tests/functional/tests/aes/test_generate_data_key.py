"""
GenerateDataKey and GenerateDataKeyWithoutPlaintext tests.

One behaviour per test.
"""
import base64
from uuid import uuid4

import pytest


# ---------------------------------------------------------------------------
# GenerateDataKey
# ---------------------------------------------------------------------------

class TestGenerateDataKey:

    def test_aes_128_plaintext_is_16_bytes(self, kms_client, symmetric_key):
        code, resp = kms_client.post("GenerateDataKey", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_128",
        })
        assert code == 200
        assert len(base64.b64decode(resp["Plaintext"])) == 16

    def test_aes_256_plaintext_is_32_bytes(self, kms_client, symmetric_key):
        code, resp = kms_client.post("GenerateDataKey", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_256",
        })
        assert code == 200
        assert len(base64.b64decode(resp["Plaintext"])) == 32

    @pytest.mark.parametrize("n", [1, 16, 32, 512, 1024])
    def test_number_of_bytes_exact(self, kms_client, symmetric_key, n):
        code, resp = kms_client.post("GenerateDataKey", {
            "KeyId": symmetric_key["KeyId"], "NumberOfBytes": n,
        })
        assert code == 200
        assert len(base64.b64decode(resp["Plaintext"])) == n

    def test_response_contains_required_fields(self, kms_client, symmetric_key):
        code, resp = kms_client.post("GenerateDataKey", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_256",
        })
        assert code == 200
        assert {"KeyId", "Plaintext", "CiphertextBlob"}.issubset(resp.keys())

    def test_key_id_in_response_is_arn(self, kms_client, symmetric_key):
        """KeyId in response is always full ARN, even when called with bare key ID."""
        code, resp = kms_client.post("GenerateDataKey", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_256",
        })
        assert code == 200
        assert resp["KeyId"] == symmetric_key["Arn"]

    def test_ciphertext_blob_decrypts_to_plaintext(self, kms_client, symmetric_key):
        code, resp = kms_client.post("GenerateDataKey", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_256",
        })
        assert code == 200

        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": resp["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == resp["Plaintext"]

    def test_ciphertext_blob_with_context_requires_context_on_decrypt(self, kms_client, symmetric_key):
        ctx = {"purpose": "data-key"}
        code, resp = kms_client.post("GenerateDataKey", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_256",
            "EncryptionContext": ctx,
        })
        assert code == 200

        # Decrypt with correct context
        code, dec = kms_client.post("Decrypt", {
            "CiphertextBlob": resp["CiphertextBlob"], "EncryptionContext": ctx,
        })
        assert code == 200
        assert dec["Plaintext"] == resp["Plaintext"]

        # Decrypt without context fails
        code, _ = kms_client.post("Decrypt", {"CiphertextBlob": resp["CiphertextBlob"]})
        assert code == 400

    def test_each_call_produces_unique_data_key(self, kms_client, symmetric_key):
        _, resp1 = kms_client.post("GenerateDataKey", {"KeyId": symmetric_key["KeyId"], "KeySpec": "AES_256"})
        _, resp2 = kms_client.post("GenerateDataKey", {"KeyId": symmetric_key["KeyId"], "KeySpec": "AES_256"})
        assert resp1["Plaintext"] != resp2["Plaintext"]
        assert resp1["CiphertextBlob"] != resp2["CiphertextBlob"]

    def test_generate_via_alias(self, kms_client, symmetric_key):
        alias = f"alias/{uuid4()}"
        kms_client.post("CreateAlias", {"TargetKeyId": symmetric_key["KeyId"], "AliasName": alias})

        code, resp = kms_client.post("GenerateDataKey", {"KeyId": alias, "KeySpec": "AES_256"})
        assert code == 200
        assert resp["KeyId"] == symmetric_key["Arn"]


class TestGenerateDataKeyValidation:

    def test_missing_key_id_fails(self, kms_client):
        code, content = kms_client.post("GenerateDataKey", {"KeySpec": "AES_256"})
        assert code == 400
        assert content["__type"] == "MissingParameterException"

    def test_neither_key_spec_nor_number_of_bytes_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("GenerateDataKey", {"KeyId": symmetric_key["KeyId"]})
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_both_key_spec_and_number_of_bytes_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("GenerateDataKey", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_256", "NumberOfBytes": 32,
        })
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_number_of_bytes_zero_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("GenerateDataKey", {
            "KeyId": symmetric_key["KeyId"], "NumberOfBytes": 0,
        })
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_number_of_bytes_over_1024_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("GenerateDataKey", {
            "KeyId": symmetric_key["KeyId"], "NumberOfBytes": 1025,
        })
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_number_of_bytes_1024_succeeds(self, kms_client, symmetric_key):
        code, resp = kms_client.post("GenerateDataKey", {
            "KeyId": symmetric_key["KeyId"], "NumberOfBytes": 1024,
        })
        assert code == 200
        assert len(base64.b64decode(resp["Plaintext"])) == 1024

    def test_invalid_key_spec_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("GenerateDataKey", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_512",
        })
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_sign_verify_key_fails(self, kms_client, rsa_signing_key):
        """SIGN_VERIFY key cannot generate data keys."""
        code, content = kms_client.post("GenerateDataKey", {
            "KeyId": rsa_signing_key["KeyId"], "KeySpec": "AES_256",
        })
        assert code == 400
        assert content["__type"] == "InvalidKeyUsageException"

    def test_disabled_key_fails(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("DisableKey", {"KeyId": key_id})

        code, content = kms_client.post("GenerateDataKey", {"KeyId": key_id, "KeySpec": "AES_256"})
        assert code == 400
        assert content["__type"] == "DisabledException"

    def test_pending_deletion_key_fails(self, kms_client):
        """Key in PendingDeletion state must return KMSInvalidStateException."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})

        code, content = kms_client.post("GenerateDataKey", {"KeyId": key_id, "KeySpec": "AES_256"})
        assert code == 400
        assert content["__type"] == "KMSInvalidStateException"

    def test_nonexistent_key_fails(self, kms_client):
        code, content = kms_client.post("GenerateDataKey", {
            "KeyId": str(uuid4()), "KeySpec": "AES_256",
        })
        assert code == 400
        assert content["__type"] == "NotFoundException"

    def test_ecc_signing_key_fails(self, kms_client, ecc_signing_key):
        """ECC SIGN_VERIFY key cannot generate data keys; must return InvalidKeyUsageException."""
        code, content = kms_client.post("GenerateDataKey", {
            "KeyId": ecc_signing_key["KeyId"], "KeySpec": "AES_256",
        })
        assert code == 400
        assert content["__type"] == "InvalidKeyUsageException"


# ---------------------------------------------------------------------------
# GenerateDataKeyWithoutPlaintext
# ---------------------------------------------------------------------------

class TestGenerateDataKeyWithoutPlaintext:

    def test_plaintext_absent_from_response(self, kms_client, symmetric_key):
        code, resp = kms_client.post("GenerateDataKeyWithoutPlaintext", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_256",
        })
        assert code == 200
        assert "CiphertextBlob" in resp
        assert "KeyId" in resp
        assert "Plaintext" not in resp

    def test_aes_256_blob_decrypts_to_32_bytes(self, kms_client, symmetric_key):
        code, resp = kms_client.post("GenerateDataKeyWithoutPlaintext", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_256",
        })
        assert code == 200
        _, dec = kms_client.post("Decrypt", {"CiphertextBlob": resp["CiphertextBlob"]})
        assert len(base64.b64decode(dec["Plaintext"])) == 32

    def test_aes_128_blob_decrypts_to_16_bytes(self, kms_client, symmetric_key):
        code, resp = kms_client.post("GenerateDataKeyWithoutPlaintext", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_128",
        })
        assert code == 200
        _, dec = kms_client.post("Decrypt", {"CiphertextBlob": resp["CiphertextBlob"]})
        assert len(base64.b64decode(dec["Plaintext"])) == 16

    def test_context_required_on_decrypt(self, kms_client, symmetric_key):
        ctx = {"use": "encrypt-then-mac"}
        _, resp = kms_client.post("GenerateDataKeyWithoutPlaintext", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_256",
            "EncryptionContext": ctx,
        })
        code, _ = kms_client.post("Decrypt", {"CiphertextBlob": resp["CiphertextBlob"]})
        assert code == 400

        code, dec = kms_client.post("Decrypt", {
            "CiphertextBlob": resp["CiphertextBlob"], "EncryptionContext": ctx,
        })
        assert code == 200

    def test_key_id_in_response_is_arn(self, kms_client, symmetric_key):
        code, resp = kms_client.post("GenerateDataKeyWithoutPlaintext", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_256",
        })
        assert code == 200
        assert resp["KeyId"] == symmetric_key["Arn"]


class TestGenerateDataKeyWithoutPlaintextValidation:

    def test_missing_key_id_fails(self, kms_client):
        code, content = kms_client.post("GenerateDataKeyWithoutPlaintext", {"KeySpec": "AES_256"})
        assert code == 400
        assert content["__type"] == "MissingParameterException"

    def test_neither_key_spec_nor_number_of_bytes_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("GenerateDataKeyWithoutPlaintext", {
            "KeyId": symmetric_key["KeyId"],
        })
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_both_key_spec_and_number_of_bytes_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("GenerateDataKeyWithoutPlaintext", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_256", "NumberOfBytes": 32,
        })
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_invalid_key_spec_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("GenerateDataKeyWithoutPlaintext", {
            "KeyId": symmetric_key["KeyId"], "KeySpec": "AES_512",
        })
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_sign_verify_key_fails(self, kms_client, rsa_signing_key):
        code, content = kms_client.post("GenerateDataKeyWithoutPlaintext", {
            "KeyId": rsa_signing_key["KeyId"], "KeySpec": "AES_256",
        })
        assert code == 400
        assert content["__type"] == "InvalidKeyUsageException"

    def test_disabled_key_fails(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("DisableKey", {"KeyId": key_id})

        code, content = kms_client.post("GenerateDataKeyWithoutPlaintext", {
            "KeyId": key_id, "KeySpec": "AES_256",
        })
        assert code == 400
        assert content["__type"] == "DisabledException"

    def test_pending_deletion_key_fails(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})

        code, content = kms_client.post("GenerateDataKeyWithoutPlaintext", {
            "KeyId": key_id, "KeySpec": "AES_256",
        })
        assert code == 400
        assert content["__type"] == "KMSInvalidStateException"

    def test_nonexistent_key_fails(self, kms_client):
        code, content = kms_client.post("GenerateDataKeyWithoutPlaintext", {
            "KeyId": str(uuid4()), "KeySpec": "AES_256",
        })
        assert code == 400
        assert content["__type"] == "NotFoundException"

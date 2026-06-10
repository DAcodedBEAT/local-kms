import base64
import pytest
from uuid import uuid4
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


class TestGetPublicKey:

    def test_get_rsa_signing_key_response_fields(self, kms_client, rsa_signing_key):
        """Response must include KeyId, PublicKey, KeySpec, KeyUsage, SigningAlgorithms."""
        code, resp = kms_client.post("GetPublicKey", {"KeyId": rsa_signing_key["KeyId"]})
        assert code == 200
        assert resp["KeyId"] == rsa_signing_key["Arn"]
        assert resp["KeySpec"] == "RSA_2048"
        assert resp["KeyUsage"] == "SIGN_VERIFY"
        assert "SigningAlgorithms" in resp
        assert len(resp["SigningAlgorithms"]) > 0
        assert "EncryptionAlgorithms" not in resp

    def test_get_rsa_encryption_key_response_fields(self, kms_client, rsa_encryption_key):
        """RSA ENCRYPT_DECRYPT key must have EncryptionAlgorithms, not SigningAlgorithms."""
        code, resp = kms_client.post("GetPublicKey", {"KeyId": rsa_encryption_key["KeyId"]})
        assert code == 200
        assert resp["KeyId"] == rsa_encryption_key["Arn"]
        assert resp["KeySpec"] == "RSA_2048"
        assert resp["KeyUsage"] == "ENCRYPT_DECRYPT"
        assert "EncryptionAlgorithms" in resp
        assert len(resp["EncryptionAlgorithms"]) > 0
        assert "SigningAlgorithms" not in resp

    def test_get_ecc_public_key_response_fields(self, kms_client, ecc_signing_key):
        """ECC key response must include KeySpec, KeyUsage, SigningAlgorithms."""
        code, resp = kms_client.post("GetPublicKey", {"KeyId": ecc_signing_key["KeyId"]})
        assert code == 200
        assert resp["KeyId"] == ecc_signing_key["Arn"]
        assert resp["KeySpec"] == "ECC_NIST_P256"
        assert resp["KeyUsage"] == "SIGN_VERIFY"
        assert "SigningAlgorithms" in resp

    def test_public_key_is_valid_rsa_der(self, kms_client, rsa_signing_key):
        """PublicKey must be a valid DER-encoded RSA public key (not private key)."""
        code, resp = kms_client.post("GetPublicKey", {"KeyId": rsa_signing_key["KeyId"]})
        assert code == 200
        pub_key_der = base64.b64decode(resp["PublicKey"])
        rsa_key = RSA.import_key(pub_key_der)
        assert rsa_key.has_private() is False
        assert rsa_key.n > 0

    def test_public_key_is_valid_ecc_der(self, kms_client, ecc_signing_key):
        """PublicKey must be a valid DER-encoded ECC public key."""
        code, resp = kms_client.post("GetPublicKey", {"KeyId": ecc_signing_key["KeyId"]})
        assert code == 200
        pub_key_der = base64.b64decode(resp["PublicKey"])
        ecc_key = ECC.import_key(pub_key_der)
        assert ecc_key.has_private() is False

    def test_get_public_key_via_alias(self, kms_client, rsa_signing_key):
        """GetPublicKey can be called with an alias."""
        alias = f"alias/{uuid4()}"
        kms_client.post("CreateAlias", {"TargetKeyId": rsa_signing_key["KeyId"], "AliasName": alias})
        code, resp = kms_client.post("GetPublicKey", {"KeyId": alias})
        assert code == 200
        assert resp["KeyId"] == rsa_signing_key["Arn"]

    def test_get_public_key_symmetric_fails(self, kms_client, symmetric_key):
        """Symmetric keys have no public key; AWS returns InvalidKeyUsageException."""
        code, resp = kms_client.post("GetPublicKey", {"KeyId": symmetric_key["KeyId"]})
        assert code == 400
        assert resp["__type"] == "InvalidKeyUsageException"

    def test_get_public_key_nonexistent_key_fails(self, kms_client):
        """Non-existent key ID must return NotFoundException."""
        code, resp = kms_client.post("GetPublicKey", {"KeyId": str(uuid4())})
        assert code == 400
        assert resp["__type"] == "NotFoundException"

    def test_rsa_public_key_can_encrypt_kms_can_decrypt(self, kms_client, rsa_encryption_key):
        """
        Public key exported from KMS must be usable for external encryption;
        KMS must be able to decrypt the result.
        """
        code, resp = kms_client.post("GetPublicKey", {"KeyId": rsa_encryption_key["KeyId"]})
        assert code == 200

        pub_key = RSA.import_key(base64.b64decode(resp["PublicKey"]))
        plaintext = b"external encryption test"
        cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
        ciphertext = cipher.encrypt(plaintext)

        code, dec = kms_client.post("Decrypt", {
            "KeyId": rsa_encryption_key["KeyId"],
            "CiphertextBlob": base64.b64encode(ciphertext).decode(),
            "EncryptionAlgorithm": "RSAES_OAEP_SHA_256",
        })
        assert code == 200
        assert base64.b64decode(dec["Plaintext"]) == plaintext

    def test_get_public_key_disabled_key_fails(self, kms_client):
        """GetPublicKey on a disabled key must fail."""
        _, resp = kms_client.post("CreateKey", {
            "KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY",
        })
        key_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("DisableKey", {"KeyId": key_id})

        code, content = kms_client.post("GetPublicKey", {"KeyId": key_id})
        assert code == 400
        assert content["__type"] == "DisabledException"

    def test_missing_key_id_fails(self, kms_client):
        """KeyId is required; omitting it must return ValidationException."""
        code, content = kms_client.post("GetPublicKey", {})
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_pending_deletion_key_fails(self, kms_client):
        """GetPublicKey on a key scheduled for deletion must return KMSInvalidStateException."""
        _, resp = kms_client.post("CreateKey", {"KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY"})
        key_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})

        code, content = kms_client.post("GetPublicKey", {"KeyId": key_id})
        assert code == 400
        assert content["__type"] == "KMSInvalidStateException"

    def test_pending_import_key_fails(self, kms_client):
        """GetPublicKey on a PendingImport (EXTERNAL origin) key must return KMSInvalidStateException."""
        _, resp = kms_client.post("CreateKey", {"Origin": "EXTERNAL"})
        key_id = resp["KeyMetadata"]["KeyId"]

        code, content = kms_client.post("GetPublicKey", {"KeyId": key_id})
        assert code == 400
        assert content["__type"] == "KMSInvalidStateException"

    def test_customer_master_key_spec_equals_key_spec(self, kms_client, rsa_signing_key):
        """CustomerMasterKeySpec (deprecated) must be present and equal to KeySpec."""
        code, resp = kms_client.post("GetPublicKey", {"KeyId": rsa_signing_key["KeyId"]})
        assert code == 200
        assert "CustomerMasterKeySpec" in resp
        assert resp["CustomerMasterKeySpec"] == resp["KeySpec"]

    def test_rsa_signing_algorithms_are_complete(self, kms_client, rsa_signing_key):
        """RSA SIGN_VERIFY key must list all 6 RSA signing algorithms."""
        code, resp = kms_client.post("GetPublicKey", {"KeyId": rsa_signing_key["KeyId"]})
        assert code == 200
        assert set(resp["SigningAlgorithms"]) == {
            "RSASSA_PSS_SHA_256", "RSASSA_PSS_SHA_384", "RSASSA_PSS_SHA_512",
            "RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PKCS1_V1_5_SHA_384", "RSASSA_PKCS1_V1_5_SHA_512",
        }

    def test_rsa_encryption_algorithms_are_complete(self, kms_client, rsa_encryption_key):
        """RSA ENCRYPT_DECRYPT key must list RSAES_OAEP_SHA_1 and RSAES_OAEP_SHA_256."""
        code, resp = kms_client.post("GetPublicKey", {"KeyId": rsa_encryption_key["KeyId"]})
        assert code == 200
        assert set(resp["EncryptionAlgorithms"]) == {"RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256"}

    def test_ecc_p256_signing_algorithm(self, kms_client, ecc_signing_key):
        """ECC_NIST_P256 key must list exactly ECDSA_SHA_256."""
        code, resp = kms_client.post("GetPublicKey", {"KeyId": ecc_signing_key["KeyId"]})
        assert code == 200
        assert resp["SigningAlgorithms"] == ["ECDSA_SHA_256"]

    def test_public_key_field_is_present(self, kms_client, rsa_signing_key):
        """PublicKey field must be present and non-empty."""
        code, resp = kms_client.post("GetPublicKey", {"KeyId": rsa_signing_key["KeyId"]})
        assert code == 200
        assert "PublicKey" in resp
        assert len(base64.b64decode(resp["PublicKey"])) > 0

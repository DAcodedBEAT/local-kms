"""
ReEncrypt tests.

One behaviour per test.
"""
import base64
from uuid import uuid4

import pytest


def _pt(data: bytes = b"reencrypt payload") -> str:
    return base64.b64encode(data).decode()


class TestReEncryptBasic:

    def test_same_key_roundtrip(self, kms_client, symmetric_key):
        """ReEncrypt same-key produces a new decryptable ciphertext."""
        pt = _pt()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})

        code, reenc = kms_client.post("ReEncrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "DestinationKeyId": symmetric_key["KeyId"],
        })
        assert code == 200
        assert {"CiphertextBlob", "KeyId", "SourceKeyId"}.issubset(reenc.keys())

        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": reenc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_different_destination_key(self, kms_client, symmetric_key):
        """ReEncrypt to a different key; SourceKeyId and KeyId reflect the two keys."""
        _, dest = kms_client.post("CreateKey", {})
        dest_id = dest["KeyMetadata"]["KeyId"]
        dest_arn = dest["KeyMetadata"]["Arn"]
        pt = _pt()

        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        code, reenc = kms_client.post("ReEncrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "DestinationKeyId": dest_id,
        })
        assert code == 200
        assert reenc["SourceKeyId"] == symmetric_key["Arn"]
        assert reenc["KeyId"] == dest_arn

        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": reenc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_result_ciphertext_differs_from_source(self, kms_client, symmetric_key):
        """New ciphertext must be different from the source (fresh nonce)."""
        pt = _pt()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        _, reenc = kms_client.post("ReEncrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "DestinationKeyId": symmetric_key["KeyId"],
        })
        assert enc["CiphertextBlob"] != reenc["CiphertextBlob"]

    def test_via_alias_destination(self, kms_client, symmetric_key):
        """DestinationKeyId may be an alias."""
        alias = f"alias/{uuid4()}"
        kms_client.post("CreateAlias", {"TargetKeyId": symmetric_key["KeyId"], "AliasName": alias})
        pt = _pt()

        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        code, reenc = kms_client.post("ReEncrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "DestinationKeyId": alias,
        })
        assert code == 200

        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": reenc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_response_has_encryption_algorithm_fields(self, kms_client, symmetric_key):
        """Response includes SourceEncryptionAlgorithm and DestinationEncryptionAlgorithm."""
        pt = _pt()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        code, reenc = kms_client.post("ReEncrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "DestinationKeyId": symmetric_key["KeyId"],
        })
        assert code == 200, reenc
        assert "SourceEncryptionAlgorithm" in reenc, reenc
        assert "DestinationEncryptionAlgorithm" in reenc, reenc
        assert reenc["SourceEncryptionAlgorithm"] == "SYMMETRIC_DEFAULT"
        assert reenc["DestinationEncryptionAlgorithm"] == "SYMMETRIC_DEFAULT"


class TestReEncryptContext:

    def test_source_context_required_when_used_for_encrypt(self, kms_client, symmetric_key):
        """Source context must match the context used during original encryption."""
        ctx = {"original": "context"}
        pt = _pt()
        _, enc = kms_client.post("Encrypt", {
            "KeyId": symmetric_key["KeyId"], "Plaintext": pt, "EncryptionContext": ctx,
        })

        code, reenc = kms_client.post("ReEncrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "DestinationKeyId": symmetric_key["KeyId"],
            "SourceEncryptionContext": ctx,
        })
        assert code == 200

    def test_wrong_source_context_fails(self, kms_client, symmetric_key):
        ctx = {"original": "context"}
        pt = _pt()
        _, enc = kms_client.post("Encrypt", {
            "KeyId": symmetric_key["KeyId"], "Plaintext": pt, "EncryptionContext": ctx,
        })

        code, _ = kms_client.post("ReEncrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "DestinationKeyId": symmetric_key["KeyId"],
            "SourceEncryptionContext": {"original": "wrong"},
        })
        assert code == 400

    def test_destination_context_required_on_subsequent_decrypt(self, kms_client, symmetric_key):
        """Destination context binds to re-encrypted blob; must supply on decrypt."""
        dest_ctx = {"new": "context"}
        pt = _pt()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        _, reenc = kms_client.post("ReEncrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "DestinationKeyId": symmetric_key["KeyId"],
            "DestinationEncryptionContext": dest_ctx,
        })

        # Without context → fail
        code, _ = kms_client.post("Decrypt", {"CiphertextBlob": reenc["CiphertextBlob"]})
        assert code == 400

        # With correct context → succeed
        code, dec = kms_client.post("Decrypt", {
            "CiphertextBlob": reenc["CiphertextBlob"], "EncryptionContext": dest_ctx,
        })
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_context_preserved_across_key_change(self, kms_client, symmetric_key):
        """Source context consumed, destination context applied independently."""
        src_ctx = {"src": "v1"}
        dst_ctx = {"dst": "v2"}
        pt = _pt()

        _, enc = kms_client.post("Encrypt", {
            "KeyId": symmetric_key["KeyId"], "Plaintext": pt, "EncryptionContext": src_ctx,
        })
        _, dest = kms_client.post("CreateKey", {})
        code, reenc = kms_client.post("ReEncrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "DestinationKeyId": dest["KeyMetadata"]["KeyId"],
            "SourceEncryptionContext": src_ctx,
            "DestinationEncryptionContext": dst_ctx,
        })
        assert code == 200

        code, dec = kms_client.post("Decrypt", {
            "CiphertextBlob": reenc["CiphertextBlob"], "EncryptionContext": dst_ctx,
        })
        assert code == 200
        assert dec["Plaintext"] == pt


class TestReEncryptValidation:

    def test_missing_destination_key_id_fails(self, kms_client, symmetric_key):
        pt = _pt()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        code, content = kms_client.post("ReEncrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 400, content
        assert content["__type"] == "MissingParameterException"

    def test_missing_ciphertext_blob_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("ReEncrypt", {"DestinationKeyId": symmetric_key["KeyId"]})
        assert code == 400, content
        assert content["__type"] == "MissingParameterException"

    def test_nonexistent_destination_key_fails(self, kms_client, symmetric_key):
        pt = _pt()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        code, content = kms_client.post("ReEncrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "DestinationKeyId": str(uuid4()),
        })
        assert code == 400, content
        assert content["__type"] == "NotFoundException"

    def test_disabled_destination_key_fails(self, kms_client, symmetric_key):
        _, resp = kms_client.post("CreateKey", {})
        dest_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("DisableKey", {"KeyId": dest_id})

        pt = _pt()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        code, content = kms_client.post("ReEncrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "DestinationKeyId": dest_id,
        })
        assert code == 400, content
        assert content["__type"] == "DisabledException"

    def test_pending_deletion_destination_key_fails(self, kms_client, symmetric_key):
        _, resp = kms_client.post("CreateKey", {})
        dest_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("ScheduleKeyDeletion", {"KeyId": dest_id, "PendingWindowInDays": 7})

        pt = _pt()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        code, content = kms_client.post("ReEncrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "DestinationKeyId": dest_id,
        })
        assert code == 400, content
        assert content["__type"] == "KMSInvalidStateException"

    def test_sign_verify_destination_key_fails(self, kms_client, symmetric_key, rsa_signing_key):
        pt = _pt()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        code, content = kms_client.post("ReEncrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "DestinationKeyId": rsa_signing_key["KeyId"],
        })
        assert code == 400
        assert content["__type"] == "InvalidKeyUsageException"

    def test_tampered_ciphertext_fails(self, kms_client, symmetric_key):
        pt = _pt()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        blob = bytearray(base64.b64decode(enc["CiphertextBlob"]))
        blob[-1] ^= 0xFF
        code, _ = kms_client.post("ReEncrypt", {
            "CiphertextBlob": base64.b64encode(bytes(blob)).decode(),
            "DestinationKeyId": symmetric_key["KeyId"],
        })
        assert code == 400

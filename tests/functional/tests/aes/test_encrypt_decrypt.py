"""
AES (SYMMETRIC_DEFAULT) encrypt/decrypt tests.

One behaviour per test. Covers: basic roundtrip, encryption context,
input validation, key state checks, and key rotation compatibility.
"""
import base64
import struct
from uuid import uuid4

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def plaintext_b64(data: bytes = b"Hello, World!") -> str:
    return base64.b64encode(data).decode()


# ---------------------------------------------------------------------------
# Basic roundtrip
# ---------------------------------------------------------------------------

class TestBasicRoundtrip:

    def test_encrypt_decrypt_by_key_id(self, kms_client, symmetric_key):
        pt = plaintext_b64()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_encrypt_decrypt_by_key_arn(self, kms_client, symmetric_key):
        pt = plaintext_b64()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["Arn"], "Plaintext": pt})
        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt
        assert dec["KeyId"] == symmetric_key["Arn"]

    def test_encrypt_via_alias_decrypt_without_key_id(self, kms_client, symmetric_key):
        """Blob embeds key ARN; decrypt without specifying KeyId succeeds."""
        alias = f"alias/{uuid4()}"
        kms_client.post("CreateAlias", {"TargetKeyId": symmetric_key["KeyId"], "AliasName": alias})
        pt = plaintext_b64()
        _, enc = kms_client.post("Encrypt", {"KeyId": alias, "Plaintext": pt})
        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_encrypt_returns_key_arn_not_alias(self, kms_client, symmetric_key):
        """KeyId in Encrypt response is always the full ARN."""
        alias = f"alias/{uuid4()}"
        kms_client.post("CreateAlias", {"TargetKeyId": symmetric_key["KeyId"], "AliasName": alias})
        _, enc = kms_client.post("Encrypt", {"KeyId": alias, "Plaintext": plaintext_b64()})
        assert enc["KeyId"] == symmetric_key["Arn"]

    def test_ciphertext_differs_each_call(self, kms_client, symmetric_key):
        """AES-GCM random nonce means identical plaintext produces different ciphertext."""
        pt = plaintext_b64()
        _, enc1 = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        _, enc2 = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        assert enc1["CiphertextBlob"] != enc2["CiphertextBlob"]

    def test_decrypt_returns_correct_key_arn(self, kms_client, symmetric_key):
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": plaintext_b64()})
        _, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert dec["KeyId"] == symmetric_key["Arn"]


# ---------------------------------------------------------------------------
# Encryption context
# ---------------------------------------------------------------------------

class TestEncryptionContext:

    def test_context_roundtrip(self, kms_client, symmetric_key):
        ctx = {"service": "my-app", "env": "test"}
        pt = plaintext_b64()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt, "EncryptionContext": ctx})
        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"], "EncryptionContext": ctx})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_missing_context_on_decrypt_fails(self, kms_client, symmetric_key):
        """Context is part of GCM AAD; omitting it on decrypt causes auth failure."""
        pt = plaintext_b64()
        _, enc = kms_client.post("Encrypt", {
            "KeyId": symmetric_key["KeyId"], "Plaintext": pt,
            "EncryptionContext": {"key": "value"},
        })
        code, _ = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 400

    def test_wrong_context_value_on_decrypt_fails(self, kms_client, symmetric_key):
        pt = plaintext_b64()
        _, enc = kms_client.post("Encrypt", {
            "KeyId": symmetric_key["KeyId"], "Plaintext": pt,
            "EncryptionContext": {"key": "correct"},
        })
        code, _ = kms_client.post("Decrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "EncryptionContext": {"key": "wrong"},
        })
        assert code == 400

    def test_extra_context_key_on_decrypt_fails(self, kms_client, symmetric_key):
        pt = plaintext_b64()
        _, enc = kms_client.post("Encrypt", {
            "KeyId": symmetric_key["KeyId"], "Plaintext": pt,
            "EncryptionContext": {"key": "value"},
        })
        code, _ = kms_client.post("Decrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "EncryptionContext": {"key": "value", "extra": "unexpected"},
        })
        assert code == 400

    def test_context_key_order_independent(self, kms_client, symmetric_key):
        """Both sides sort context by key before using as AAD."""
        pt = plaintext_b64()
        _, enc = kms_client.post("Encrypt", {
            "KeyId": symmetric_key["KeyId"], "Plaintext": pt,
            "EncryptionContext": {"z-key": "z-val", "a-key": "a-val"},
        })
        code, dec = kms_client.post("Decrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "EncryptionContext": {"a-key": "a-val", "z-key": "z-val"},
        })
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_no_context_encrypt_no_context_decrypt_succeeds(self, kms_client, symmetric_key):
        """Omitting context on both sides is fine."""
        pt = plaintext_b64()
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_context_with_decrypt_key_id_specified(self, kms_client, symmetric_key):
        """Explicit KeyId on Decrypt still requires matching context."""
        ctx = {"app": "test"}
        pt = plaintext_b64()
        _, enc = kms_client.post("Encrypt", {
            "KeyId": symmetric_key["KeyId"], "Plaintext": pt, "EncryptionContext": ctx,
        })
        code, dec = kms_client.post("Decrypt", {
            "KeyId": symmetric_key["KeyId"],
            "CiphertextBlob": enc["CiphertextBlob"],
            "EncryptionContext": ctx,
        })
        assert code == 200
        assert dec["Plaintext"] == pt


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class TestEncryptValidation:

    def test_empty_plaintext_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": ""})
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_plaintext_over_4096_bytes_fails(self, kms_client, symmetric_key):
        big = base64.b64encode(b"x" * 4097).decode()
        code, content = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": big})
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_plaintext_exactly_4096_bytes_succeeds(self, kms_client, symmetric_key):
        data = base64.b64encode(b"x" * 4096).decode()
        code, _ = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": data})
        assert code == 200

    def test_missing_key_id_fails(self, kms_client):
        code, content = kms_client.post("Encrypt", {"Plaintext": plaintext_b64()})
        assert code == 400

    def test_nonexistent_key_id_fails(self, kms_client):
        code, content = kms_client.post("Encrypt", {"KeyId": str(uuid4()), "Plaintext": plaintext_b64()})
        assert code == 400
        assert content["__type"] == "NotFoundException"


class TestDecryptValidation:

    def test_missing_ciphertext_fails(self, kms_client):
        code, content = kms_client.post("Decrypt", {})
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_empty_ciphertext_fails(self, kms_client):
        code, content = kms_client.post("Decrypt", {"CiphertextBlob": ""})
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_decrypt_explicit_wrong_key_id_fails(self, kms_client):
        """Supplying a KeyId that does not own the ciphertext must return AccessDeniedException."""
        _, r1 = kms_client.post("CreateKey", {})
        _, r2 = kms_client.post("CreateKey", {})
        key1_id = r1["KeyMetadata"]["KeyId"]
        key2_id = r2["KeyMetadata"]["KeyId"]

        _, enc = kms_client.post("Encrypt", {"KeyId": key1_id, "Plaintext": plaintext_b64()})

        code, content = kms_client.post("Decrypt", {
            "CiphertextBlob": enc["CiphertextBlob"],
            "KeyId": key2_id,
        })
        assert code == 400
        assert content["__type"] == "AccessDeniedException"


# ---------------------------------------------------------------------------
# Key state
# ---------------------------------------------------------------------------

class TestKeyState:

    def test_disabled_key_encrypt_fails(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("DisableKey", {"KeyId": key_id})

        code, content = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": plaintext_b64()})
        assert code == 400
        assert content["__type"] == "DisabledException"

    def test_disabled_key_decrypt_with_key_id_fails(self, kms_client):
        """Decrypt with explicit disabled KeyId returns DisabledException."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        pt = plaintext_b64()
        _, enc = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})

        kms_client.post("DisableKey", {"KeyId": key_id})

        code, content = kms_client.post("Decrypt", {
            "KeyId": key_id,
            "CiphertextBlob": enc["CiphertextBlob"],
        })
        assert code == 400
        assert content["__type"] == "DisabledException"

    def test_disabled_key_decrypt_without_key_id_fails(self, kms_client):
        """Decrypt using embedded ARN on a disabled key returns 400."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        pt = plaintext_b64()
        _, enc = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})

        kms_client.post("DisableKey", {"KeyId": key_id})

        code, _ = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 400

    def test_reenable_key_restores_encrypt_decrypt(self, kms_client):
        """Re-enabled key works for both encrypt and decrypt of pre-disable ciphertext."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        pt = plaintext_b64()

        _, enc_before = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})

        kms_client.post("DisableKey", {"KeyId": key_id})
        kms_client.post("EnableKey", {"KeyId": key_id})

        # Old ciphertext still decryptable
        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc_before["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt

        # New encrypt/decrypt also works
        _, enc_after = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})
        code, dec2 = kms_client.post("Decrypt", {"CiphertextBlob": enc_after["CiphertextBlob"]})
        assert code == 200
        assert dec2["Plaintext"] == pt

    def test_pending_deletion_key_encrypt_fails(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})

        code, content = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": plaintext_b64()})
        assert code == 400
        assert content["__type"] == "KMSInvalidStateException"

    def test_cancelled_deletion_key_encrypt_succeeds(self, kms_client):
        """CancelKeyDeletion restores key to Disabled; must re-enable to encrypt."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        pt = plaintext_b64()

        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})
        kms_client.post("CancelKeyDeletion", {"KeyId": key_id})
        kms_client.post("EnableKey", {"KeyId": key_id})

        code, enc = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})
        assert code == 200
        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_sign_verify_key_encrypt_fails(self, kms_client, rsa_signing_key):
        code, content = kms_client.post("Encrypt", {
            "KeyId": rsa_signing_key["KeyId"], "Plaintext": plaintext_b64(),
        })
        assert code == 400
        assert content["__type"] == "InvalidKeyUsageException"

    def test_ecc_sign_verify_key_encrypt_fails(self, kms_client, ecc_signing_key):
        code, content = kms_client.post("Encrypt", {
            "KeyId": ecc_signing_key["KeyId"], "Plaintext": plaintext_b64(),
        })
        assert code == 400
        assert content["__type"] == "InvalidKeyUsageException"


# ---------------------------------------------------------------------------
# Key rotation compatibility
# ---------------------------------------------------------------------------

class TestKeyRotation:

    def test_old_ciphertext_decryptable_after_rotation_enabled(self, kms_client):
        """
        Ciphertext blob embeds backing-key version index.
        Enabling rotation must not invalidate existing ciphertext.
        """
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        pt = plaintext_b64(b"pre-rotation data")

        _, enc = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})
        pre_blob = enc["CiphertextBlob"]

        code, _ = kms_client.post("EnableKeyRotation", {"KeyId": key_id})
        assert code == 200

        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": pre_blob})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_new_encrypt_works_after_rotation_enabled(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        pt = plaintext_b64(b"post-rotation-enable data")

        kms_client.post("EnableKeyRotation", {"KeyId": key_id})

        _, enc = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})
        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_rotation_disabled_then_encrypt_decrypt(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        pt = plaintext_b64()

        kms_client.post("EnableKeyRotation", {"KeyId": key_id})
        code, _ = kms_client.post("DisableKeyRotation", {"KeyId": key_id})
        assert code == 200

        _, enc = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})
        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt


# ---------------------------------------------------------------------------
# RSA encryption size limits
# ---------------------------------------------------------------------------

class TestRsaEncryptSizeLimits:
    """
    AWS enforces per-algorithm plaintext size limits for RSA encryption keys.
    RSA_2048 / RSAES_OAEP_SHA_256: max 190 bytes.
    RSA_2048 / RSAES_OAEP_SHA_1:   max 214 bytes.
    """

    def test_oaep_sha256_over_limit_fails(self, kms_client, rsa_encryption_key):
        """191 bytes exceeds the 190-byte limit for RSA_2048 OAEP-SHA-256."""
        oversized = base64.b64encode(b"x" * 191).decode()
        code, content = kms_client.post("Encrypt", {
            "KeyId": rsa_encryption_key["KeyId"],
            "EncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            "Plaintext": oversized,
        })
        assert code == 400
        assert content["__type"] == "InvalidKeyUsageException"

    def test_oaep_sha256_at_limit_succeeds(self, kms_client, rsa_encryption_key):
        """190 bytes is exactly the limit for RSA_2048 OAEP-SHA-256."""
        at_limit = base64.b64encode(b"x" * 190).decode()
        code, _ = kms_client.post("Encrypt", {
            "KeyId": rsa_encryption_key["KeyId"],
            "EncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            "Plaintext": at_limit,
        })
        assert code == 200

    def test_oaep_sha1_over_limit_fails(self, kms_client, rsa_encryption_key):
        """215 bytes exceeds the 214-byte limit for RSA_2048 OAEP-SHA-1."""
        oversized = base64.b64encode(b"x" * 215).decode()
        code, content = kms_client.post("Encrypt", {
            "KeyId": rsa_encryption_key["KeyId"],
            "EncryptionAlgorithm": "RSAES_OAEP_SHA_1",
            "Plaintext": oversized,
        })
        assert code == 400
        assert content["__type"] == "InvalidKeyUsageException"

    def test_oaep_sha1_at_limit_succeeds(self, kms_client, rsa_encryption_key):
        """214 bytes is exactly the limit for RSA_2048 OAEP-SHA-1."""
        at_limit = base64.b64encode(b"x" * 214).decode()
        code, _ = kms_client.post("Encrypt", {
            "KeyId": rsa_encryption_key["KeyId"],
            "EncryptionAlgorithm": "RSAES_OAEP_SHA_1",
            "Plaintext": at_limit,
        })
        assert code == 200


# ---------------------------------------------------------------------------
# Decrypt with wrong key usage
# ---------------------------------------------------------------------------

class TestDecryptKeyUsage:

    def test_decrypt_with_sign_verify_rsa_key_fails(self, kms_client, rsa_signing_key):
        """Decrypt with a SIGN_VERIFY RSA key must return InvalidKeyUsageException."""
        # Provide some bytes as ciphertext; handler checks key usage before decrypting
        dummy_ct = base64.b64encode(b"x" * 256).decode()
        code, content = kms_client.post("Decrypt", {
            "KeyId": rsa_signing_key["KeyId"],
            "CiphertextBlob": dummy_ct,
            "EncryptionAlgorithm": "RSAES_OAEP_SHA_256",
        })
        assert code == 400
        assert content["__type"] == "InvalidKeyUsageException"

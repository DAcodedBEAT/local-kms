"""
Corruption prevention tests.

Verifies that:
- Tampered / truncated / malformed ciphertext blobs are rejected without a panic
- Key state transitions don't corrupt existing ciphertext
- Alias operations can't cause decrypt failures on previously encrypted data
- The server remains responsive under repeated operations
"""
import base64
import os
import struct
from uuid import uuid4

import pytest


def _enc_b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _dec_b64(s: str) -> bytes:
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# Ciphertext blob integrity
# ---------------------------------------------------------------------------

class TestCiphertextIntegrity:

    def test_bit_flip_in_ciphertext_body_fails(self, kms_client, symmetric_key):
        """Single-bit flip triggers AES-GCM authentication failure."""
        pt = _enc_b64(b"integrity check")
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})

        blob = bytearray(_dec_b64(enc["CiphertextBlob"]))
        blob[-1] ^= 0xFF  # flip last byte (well inside ciphertext body)

        code, _ = kms_client.post("Decrypt", {"CiphertextBlob": _enc_b64(bytes(blob))})
        assert code == 400

    def test_bit_flip_in_nonce_fails(self, kms_client, symmetric_key):
        """Flipping a byte in the nonce region causes auth failure."""
        pt = _enc_b64(b"nonce integrity")
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})

        blob = bytearray(_dec_b64(enc["CiphertextBlob"]))
        arn_len = blob[0]
        # Nonce starts at offset: 1 + arn_len + 4 (version bytes)
        nonce_start = 1 + arn_len + 4
        blob[nonce_start] ^= 0x01

        code, _ = kms_client.post("Decrypt", {"CiphertextBlob": _enc_b64(bytes(blob))})
        assert code == 400

    def test_truncated_blob_fails_gracefully(self, kms_client, symmetric_key):
        """Truncated blob is rejected without a 500 or panic."""
        pt = _enc_b64(b"truncation check")
        _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})

        blob = _dec_b64(enc["CiphertextBlob"])
        truncated = blob[: len(blob) // 2]

        code, _ = kms_client.post("Decrypt", {"CiphertextBlob": _enc_b64(truncated)})
        assert code == 400

    def test_random_bytes_as_ciphertext_fails_gracefully(self, kms_client):
        """Random bytes don't crash the server."""
        code, _ = kms_client.post("Decrypt", {"CiphertextBlob": _enc_b64(os.urandom(128))})
        assert code == 400

    def test_empty_ciphertext_blob_validation_error(self, kms_client):
        code, content = kms_client.post("Decrypt", {"CiphertextBlob": ""})
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_invalid_key_version_in_blob_fails_gracefully(self, kms_client):
        """
        Version index pointing beyond BackingKeys array must fail with an error,
        not a panic or 500 from an out-of-bounds access.
        """
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        pt = _enc_b64(b"version bounds check")

        _, enc = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})

        blob = bytearray(_dec_b64(enc["CiphertextBlob"]))
        arn_len = blob[0]
        version_offset = 1 + arn_len
        # Overwrite 4-byte LE version with a large out-of-range value
        struct.pack_into("<I", blob, version_offset, 9999)

        code, _ = kms_client.post("Decrypt", {"CiphertextBlob": _enc_b64(bytes(blob))})
        assert code == 400

    def test_wrong_key_arn_in_blob_fails(self, kms_client):
        """Blob with a substituted key ARN is rejected."""
        _, resp1 = kms_client.post("CreateKey", {})
        _, resp2 = kms_client.post("CreateKey", {})
        key1_id = resp1["KeyMetadata"]["KeyId"]
        key2_arn = resp2["KeyMetadata"]["Arn"].encode()

        pt = _enc_b64(b"wrong arn test")
        _, enc = kms_client.post("Encrypt", {"KeyId": key1_id, "Plaintext": pt})

        blob = bytearray(_dec_b64(enc["CiphertextBlob"]))
        arn_len = blob[0]

        # Both keys share the same account/region so ARNs are always the same length.
        # If this ever fails the blob format has changed and the test needs updating.
        assert arn_len == len(key2_arn), (
            f"Cannot patch ARN: blob stores {arn_len} bytes but key2 ARN is {len(key2_arn)} bytes"
        )
        blob[1 : 1 + arn_len] = key2_arn
        code, _ = kms_client.post("Decrypt", {"CiphertextBlob": _enc_b64(bytes(blob))})
        assert code == 400


# ---------------------------------------------------------------------------
# Alias operations can't corrupt existing ciphertext
# ---------------------------------------------------------------------------

class TestAliasCycleIntegrity:

    def test_delete_recreate_alias_same_key_preserves_decrypt(self, kms_client, symmetric_key):
        """
        Original corruption scenario: alias delete + recreate pointing to same key
        must not break decryption of previously encrypted blobs.
        """
        alias = f"alias/{uuid4()}"
        pt = _enc_b64(b"alias recreation test")

        kms_client.post("CreateAlias", {"TargetKeyId": symmetric_key["KeyId"], "AliasName": alias})
        _, enc = kms_client.post("Encrypt", {"KeyId": alias, "Plaintext": pt})
        ciphertext = enc["CiphertextBlob"]

        kms_client.post("DeleteAlias", {"AliasName": alias})
        kms_client.post("CreateAlias", {"TargetKeyId": symmetric_key["KeyId"], "AliasName": alias})

        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": ciphertext})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_alias_retarget_old_blob_uses_original_key(self, kms_client, symmetric_key):
        """
        Blob embeds the key ARN; retargeting an alias does not change what key
        the blob decrypts with.
        """
        alias = f"alias/{uuid4()}"
        pt = _enc_b64(b"retarget test")

        kms_client.post("CreateAlias", {"TargetKeyId": symmetric_key["KeyId"], "AliasName": alias})
        _, enc = kms_client.post("Encrypt", {"KeyId": alias, "Plaintext": pt})
        ciphertext = enc["CiphertextBlob"]

        _, dest = kms_client.post("CreateKey", {})
        kms_client.post("UpdateAlias", {"AliasName": alias, "TargetKeyId": dest["KeyMetadata"]["KeyId"]})

        # Blob still decrypts using original key (alias is irrelevant once blob is created)
        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": ciphertext})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_multiple_alias_recreations_stay_consistent(self, kms_client, symmetric_key):
        """10 delete/recreate cycles on the same alias don't break decryption."""
        alias = f"alias/{uuid4()}"
        pt = _enc_b64(b"multi-cycle test")

        kms_client.post("CreateAlias", {"TargetKeyId": symmetric_key["KeyId"], "AliasName": alias})
        _, enc = kms_client.post("Encrypt", {"KeyId": alias, "Plaintext": pt})
        ciphertext = enc["CiphertextBlob"]

        for _ in range(10):
            kms_client.post("DeleteAlias", {"AliasName": alias})
            kms_client.post("CreateAlias", {"TargetKeyId": symmetric_key["KeyId"], "AliasName": alias})

        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": ciphertext})
        assert code == 200
        assert dec["Plaintext"] == pt


# ---------------------------------------------------------------------------
# Key state transitions don't corrupt data
# ---------------------------------------------------------------------------

class TestKeyStateIntegrity:

    def test_disable_enable_cycle_preserves_all_ciphertext(self, kms_client):
        """Ciphertexts made before disable are still decryptable after re-enable."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        pt = _enc_b64(b"state integrity test")

        _, enc_before = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})

        kms_client.post("DisableKey", {"KeyId": key_id})
        kms_client.post("EnableKey", {"KeyId": key_id})

        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc_before["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_rotation_enable_disable_cycle_preserves_ciphertext(self, kms_client):
        """Enabling then disabling rotation doesn't change existing key material."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        pt = _enc_b64(b"rotation toggle test")

        _, enc = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})

        kms_client.post("EnableKeyRotation", {"KeyId": key_id})
        kms_client.post("DisableKeyRotation", {"KeyId": key_id})

        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_schedule_cancel_deletion_preserves_ciphertext(self, kms_client):
        """CancelKeyDeletion restores key to Disabled; old ciphertext still decrypts after re-enabling."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        pt = _enc_b64(b"cancel deletion test")

        _, enc = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})

        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})
        kms_client.post("CancelKeyDeletion", {"KeyId": key_id})
        kms_client.post("EnableKey", {"KeyId": key_id})

        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt

    def test_tag_operations_dont_affect_encrypt_decrypt(self, kms_client):
        """Adding and removing tags must not alter key material."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        pt = _enc_b64(b"tag operation test")

        _, enc = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})

        kms_client.post("TagResource", {"KeyId": key_id, "Tags": [{"TagKey": "k", "TagValue": "v"}]})
        kms_client.post("UntagResource", {"KeyId": key_id, "TagKeys": ["k"]})

        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt


# ---------------------------------------------------------------------------
# Volume / consistency
# ---------------------------------------------------------------------------

class TestConsistency:

    def test_100_encrypt_decrypt_cycles_consistent(self, kms_client, symmetric_key):
        """100 back-to-back encrypt/decrypt operations on same key produce consistent results."""
        pt = _enc_b64(b"consistency check")

        for _ in range(100):
            _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
            code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
            assert code == 200
            assert dec["Plaintext"] == pt

    def test_concurrent_encrypt_blobs_all_decrypt_correctly(self, kms_client, symmetric_key):
        """Multiple ciphertexts produced sequentially all decrypt to correct plaintext."""
        payloads = [_enc_b64(f"payload-{i}".encode()) for i in range(20)]
        ciphertexts = []

        for pt in payloads:
            _, enc = kms_client.post("Encrypt", {"KeyId": symmetric_key["KeyId"], "Plaintext": pt})
            ciphertexts.append((pt, enc["CiphertextBlob"]))

        for pt, ct in ciphertexts:
            code, dec = kms_client.post("Decrypt", {"CiphertextBlob": ct})
            assert code == 200
            assert dec["Plaintext"] == pt

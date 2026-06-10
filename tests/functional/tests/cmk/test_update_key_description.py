import base64

import pytest
from uuid import uuid4


class TestUpdateKeyDescription:

    def test_update_description_success(self, kms_client, symmetric_key):
        code, _ = kms_client.post("UpdateKeyDescription", {
            "KeyId": symmetric_key['KeyId'],
            "Description": "Updated description",
        })
        assert code == 200

        code, resp = kms_client.post("DescribeKey", {"KeyId": symmetric_key['KeyId']})
        assert code == 200
        assert resp['KeyMetadata']['Description'] == "Updated description"

    def test_update_description_via_arn(self, kms_client, symmetric_key):
        code, _ = kms_client.post("UpdateKeyDescription", {
            "KeyId": symmetric_key['Arn'],
            "Description": "via arn",
        })
        assert code == 200

        _, resp = kms_client.post("DescribeKey", {"KeyId": symmetric_key['KeyId']})
        assert resp['KeyMetadata']['Description'] == "via arn"

    def test_update_description_empty(self, kms_client, symmetric_key):
        # First set a non-empty description
        kms_client.post("UpdateKeyDescription", {
            "KeyId": symmetric_key['KeyId'], "Description": "non-empty",
        })

        code, _ = kms_client.post("UpdateKeyDescription", {
            "KeyId": symmetric_key['KeyId'], "Description": "",
        })
        assert code == 200

    def test_update_description_max_length_succeeds(self, kms_client, symmetric_key):
        """8192-character description is at the AWS limit and must succeed."""
        desc = "x" * 8192
        code, _ = kms_client.post("UpdateKeyDescription", {
            "KeyId": symmetric_key['KeyId'], "Description": desc,
        })
        assert code == 200

    def test_update_description_over_max_fails(self, kms_client, symmetric_key):
        """8193-character description exceeds the 8192-char limit."""
        desc = "x" * 8193
        code, resp = kms_client.post("UpdateKeyDescription", {
            "KeyId": symmetric_key['KeyId'], "Description": desc,
        })
        assert code == 400
        assert resp["__type"] == "ValidationException"

    def test_description_update_does_not_affect_crypto(self, kms_client):
        """Updating description must not corrupt key material."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp['KeyMetadata']['KeyId']
        pt = base64.b64encode(b"description change test").decode()

        _, enc = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})
        kms_client.post("UpdateKeyDescription", {"KeyId": key_id, "Description": "changed"})

        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc['CiphertextBlob']})
        assert code == 200
        assert dec['Plaintext'] == pt

    def test_update_description_nonexistent_key_fails(self, kms_client):
        code, resp = kms_client.post("UpdateKeyDescription", {
            "KeyId": str(uuid4()),
            "Description": "irrelevant",
        })
        assert code == 400
        assert resp["__type"] == "NotFoundException"

    def test_missing_key_id_fails(self, kms_client):
        code, resp = kms_client.post("UpdateKeyDescription", {"Description": "no key"})
        assert code == 400
        assert resp["__type"] == "MissingParameterException"

    def test_missing_description_defaults_to_empty(self, kms_client, symmetric_key):
        """Omitting Description must not crash; handler defaults to empty string."""
        code, _ = kms_client.post("UpdateKeyDescription", {"KeyId": symmetric_key['KeyId']})
        assert code == 200
        _, described = kms_client.post("DescribeKey", {"KeyId": symmetric_key['KeyId']})
        assert described['KeyMetadata']['Description'] == ""

    def test_pending_deletion_key_fails(self, kms_client):
        """UpdateKeyDescription on a pending-deletion key must return KMSInvalidStateException."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp['KeyMetadata']['KeyId']
        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})

        code, content = kms_client.post("UpdateKeyDescription", {
            "KeyId": key_id, "Description": "should fail",
        })
        assert code == 400
        assert content["__type"] == "KMSInvalidStateException"

    def test_via_alias_fails(self, kms_client, symmetric_key):
        """UpdateKeyDescription does not resolve aliases; alias as KeyId must return NotFoundException."""
        alias = f"alias/upd-desc-{uuid4()}"
        kms_client.post("CreateAlias", {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias})

        code, content = kms_client.post("UpdateKeyDescription", {
            "KeyId": alias, "Description": "should fail",
        })
        assert code == 400
        assert content["__type"] == "NotFoundException"

    def test_disabled_key_succeeds(self, kms_client):
        """UpdateKeyDescription on a disabled key must succeed (disabled is compatible state)."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp['KeyMetadata']['KeyId']
        kms_client.post("DisableKey", {"KeyId": key_id})

        code, _ = kms_client.post("UpdateKeyDescription", {
            "KeyId": key_id, "Description": "disabled but updatable",
        })
        assert code == 200
        _, described = kms_client.post("DescribeKey", {"KeyId": key_id})
        assert described['KeyMetadata']['Description'] == "disabled but updatable"

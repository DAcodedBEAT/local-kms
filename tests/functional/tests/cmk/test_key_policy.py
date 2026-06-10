"""
Tests for GetKeyPolicy and PutKeyPolicy.
"""
import json
from uuid import uuid4


SAMPLE_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "Enable IAM User Permissions",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
        "Action": "kms:*",
        "Resource": "*",
    }]
})


class TestPutKeyPolicy:

    def test_put_policy_symmetric_key(self, kms_client):
        """PutKeyPolicy succeeds on a symmetric key."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, _ = kms_client.post('PutKeyPolicy', {
            "KeyId": key_id,
            "PolicyName": "default",
            "Policy": SAMPLE_POLICY,
        })
        assert code == 200

    def test_put_policy_rsa_key(self, kms_client):
        """PutKeyPolicy must not crash on RSA keys."""
        _, resp = kms_client.post('CreateKey', {
            "KeyUsage": "SIGN_VERIFY",
            "CustomerMasterKeySpec": "RSA_2048",
        })
        key_id = resp['KeyMetadata']['KeyId']

        code, _ = kms_client.post('PutKeyPolicy', {
            "KeyId": key_id,
            "PolicyName": "default",
            "Policy": SAMPLE_POLICY,
        })
        assert code == 200

    def test_put_policy_ecc_key(self, kms_client):
        """PutKeyPolicy must not crash on ECC keys."""
        _, resp = kms_client.post('CreateKey', {
            "KeyUsage": "SIGN_VERIFY",
            "CustomerMasterKeySpec": "ECC_NIST_P256",
        })
        key_id = resp['KeyMetadata']['KeyId']

        code, _ = kms_client.post('PutKeyPolicy', {
            "KeyId": key_id,
            "PolicyName": "default",
            "Policy": SAMPLE_POLICY,
        })
        assert code == 200

    def test_put_policy_omitted_policy_name_defaults_to_default(self, kms_client):
        """PolicyName is optional; omitting it defaults to 'default'."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, _ = kms_client.post('PutKeyPolicy', {
            "KeyId": key_id,
            "Policy": SAMPLE_POLICY,
        })
        assert code == 200

    def test_put_policy_invalid_policy_name_fails(self, kms_client):
        """PolicyName other than 'default' must return ValidationException."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, content = kms_client.post('PutKeyPolicy', {
            "KeyId": key_id,
            "PolicyName": "custom",
            "Policy": SAMPLE_POLICY,
        })
        assert code == 400
        assert content['__type'] == 'ValidationException'

    def test_put_policy_too_large_fails(self, kms_client):
        """Policy exceeding 32768 bytes must return ValidationException."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, content = kms_client.post('PutKeyPolicy', {
            "KeyId": key_id,
            "PolicyName": "default",
            "Policy": "x" * 32769,
        })
        assert code == 400
        assert content['__type'] == 'ValidationException'

    def test_put_policy_pending_deletion_key_succeeds(self, kms_client):
        """PutKeyPolicy on a PendingDeletion key must succeed (AWS allows it)."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        kms_client.post('ScheduleKeyDeletion', {"KeyId": key_id, "PendingWindowInDays": 7})

        code, _ = kms_client.post('PutKeyPolicy', {
            "KeyId": key_id,
            "PolicyName": "default",
            "Policy": SAMPLE_POLICY,
        })
        assert code == 200

    def test_put_policy_roundtrip(self, kms_client):
        """GetKeyPolicy returns policy set by PutKeyPolicy."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        kms_client.post('PutKeyPolicy', {
            "KeyId": key_id,
            "PolicyName": "default",
            "Policy": SAMPLE_POLICY,
        })

        code, content = kms_client.post('GetKeyPolicy', {
            "KeyId": key_id,
            "PolicyName": "default",
        })
        assert code == 200
        assert content['Policy'] == SAMPLE_POLICY


    def test_put_policy_nonexistent_key_fails(self, kms_client):
        """PutKeyPolicy on a nonexistent key must return NotFoundException."""
        code, content = kms_client.post('PutKeyPolicy', {
            "KeyId": str(uuid4()),
            "PolicyName": "default",
            "Policy": SAMPLE_POLICY,
        })
        assert code == 400
        assert content['__type'] == 'NotFoundException'

    def test_put_policy_alias_as_key_id_fails(self, kms_client):
        """PutKeyPolicy does not resolve aliases; alias name as KeyId must return NotFoundException."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        alias = f"alias/policy-test-{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": key_id, "AliasName": alias})

        code, content = kms_client.post('PutKeyPolicy', {
            "KeyId": alias,
            "PolicyName": "default",
            "Policy": SAMPLE_POLICY,
        })
        assert code == 400
        assert content['__type'] == 'NotFoundException'


class TestGetKeyPolicy:

    def test_get_default_policy(self, kms_client):
        """GetKeyPolicy returns a policy for a newly created key."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, content = kms_client.post('GetKeyPolicy', {
            "KeyId": key_id,
            "PolicyName": "default",
        })
        assert code == 200
        assert 'Policy' in content

    def test_get_policy_omitted_policy_name_defaults_to_default(self, kms_client):
        """PolicyName is optional in GetKeyPolicy."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, content = kms_client.post('GetKeyPolicy', {"KeyId": key_id})
        assert code == 200
        assert 'Policy' in content

    def test_get_policy_nonexistent_key_fails(self, kms_client):
        """GetKeyPolicy on a nonexistent key must return NotFoundException."""
        code, content = kms_client.post('GetKeyPolicy', {
            "KeyId": "00000000-0000-0000-0000-000000000000",
            "PolicyName": "default",
        })
        assert code == 400
        assert content['__type'] == 'NotFoundException'

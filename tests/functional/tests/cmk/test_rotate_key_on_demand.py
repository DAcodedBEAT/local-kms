"""
Tests for RotateKeyOnDemand.
"""
from tests.helpers import assert_error_response


class TestRotateKeyOnDemand:

    def test_rotate_returns_key_id(self, kms_client):
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        key_arn = resp['KeyMetadata']['Arn']

        code, content = kms_client.post('RotateKeyOnDemand', {"KeyId": key_id})
        assert code == 200
        assert content['KeyId'] == key_arn

    def test_encrypt_decrypt_round_trip_after_rotation(self, kms_client, symmetric_key):
        """Ciphertext encrypted after an on-demand rotation must still decrypt correctly."""
        key_id = symmetric_key['KeyId']

        code, unused = kms_client.post('RotateKeyOnDemand', {"KeyId": key_id})
        assert code == 200

        code, enc = kms_client.post('Encrypt', {"KeyId": key_id, "Plaintext": "aGVsbG8="})
        assert code == 200

        code, dec = kms_client.post('Decrypt', {"CiphertextBlob": enc['CiphertextBlob']})
        assert code == 200
        assert dec['Plaintext'] == "aGVsbG8="

    def test_rotate_nonexistent_key_fails(self, kms_client):
        code, content = kms_client.post('RotateKeyOnDemand', {
            "KeyId": "arn:aws:kms:eu-west-2:111122223333:key/00000000-1111-2222-3333-444444444444",
        })
        assert code == 400
        assert_error_response(content, 'NotFoundException')

    def test_rotate_rsa_key_fails(self, kms_client, rsa_signing_key):
        """UnsupportedOperationException uses a capital-M Message field, matching real AWS KMS."""
        code, content = kms_client.post('RotateKeyOnDemand', {"KeyId": rsa_signing_key['KeyId']})
        assert code == 400
        assert content['__type'] == 'UnsupportedOperationException'

    def test_rotate_ecc_key_fails(self, kms_client, ecc_signing_key):
        code, content = kms_client.post('RotateKeyOnDemand', {"KeyId": ecc_signing_key['KeyId']})
        assert code == 400
        assert content['__type'] == 'UnsupportedOperationException'

    def test_rotate_external_key_fails(self, kms_client):
        _, resp = kms_client.post('CreateKey', {"Origin": "EXTERNAL"})
        key_id = resp['KeyMetadata']['KeyId']

        code, content = kms_client.post('RotateKeyOnDemand', {"KeyId": key_id})
        assert code == 400
        assert content['__type'] == 'UnsupportedOperationException'

    def test_rotate_disabled_key_fails(self, kms_client):
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        kms_client.post('DisableKey', {"KeyId": key_id})

        code, content = kms_client.post('RotateKeyOnDemand', {"KeyId": key_id})
        assert code == 400
        assert_error_response(content, 'DisabledException')

    def test_rotate_quota_exceeded(self, kms_client):
        """AWS KMS allows at most 25 on-demand rotations per key."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        for _ in range(25):
            code, unused = kms_client.post('RotateKeyOnDemand', {"KeyId": key_id})
            assert code == 200

        code, content = kms_client.post('RotateKeyOnDemand', {"KeyId": key_id})
        assert code == 400
        assert_error_response(content, 'LimitExceededException')

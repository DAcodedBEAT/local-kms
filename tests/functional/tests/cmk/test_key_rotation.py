"""
Tests for GetKeyRotationStatus, EnableKeyRotation, DisableKeyRotation.
"""
from uuid import uuid4


class TestGetKeyRotationStatus:

    def test_rotation_disabled_by_default(self, kms_client):
        """Use a fresh key so session-scoped fixtures that enable rotation don't interfere."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, resp = kms_client.post('GetKeyRotationStatus', {"KeyId": key_id})
        assert code == 200
        assert resp['KeyRotationEnabled'] is False

    def test_response_includes_key_id(self, kms_client, symmetric_key):
        """KeyId must be present in the response."""
        code, resp = kms_client.post('GetKeyRotationStatus', {"KeyId": symmetric_key['KeyId']})
        assert code == 200
        assert 'KeyId' in resp

    def test_response_includes_rotation_period(self, kms_client, symmetric_key):
        """RotationPeriodInDays must always be present."""
        code, resp = kms_client.post('GetKeyRotationStatus', {"KeyId": symmetric_key['KeyId']})
        assert code == 200
        assert 'RotationPeriodInDays' in resp
        assert isinstance(resp['RotationPeriodInDays'], int)

    def test_next_rotation_date_present_when_enabled(self, kms_client):
        """NextRotationDate must appear in response when rotation is enabled."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        kms_client.post('EnableKeyRotation', {"KeyId": key_id})

        code, resp = kms_client.post('GetKeyRotationStatus', {"KeyId": key_id})
        assert code == 200
        assert resp['KeyRotationEnabled'] is True
        assert 'NextRotationDate' in resp
        assert isinstance(resp['NextRotationDate'], (int, float))

    def test_next_rotation_date_absent_when_disabled(self, kms_client):
        """NextRotationDate must NOT appear when rotation is disabled."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, resp = kms_client.post('GetKeyRotationStatus', {"KeyId": key_id})
        assert code == 200
        assert resp['KeyRotationEnabled'] is False
        assert 'NextRotationDate' not in resp

    def test_rsa_key_returns_unsupported_operation(self, kms_client, rsa_signing_key):
        """GetKeyRotationStatus on an RSA key must return UnsupportedOperationException."""
        code, resp = kms_client.post('GetKeyRotationStatus', {"KeyId": rsa_signing_key['KeyId']})
        assert code == 400
        assert resp['__type'] == 'UnsupportedOperationException'

    def test_ecc_key_returns_unsupported_operation(self, kms_client, ecc_signing_key):
        """GetKeyRotationStatus on an ECC key must return UnsupportedOperationException."""
        code, resp = kms_client.post('GetKeyRotationStatus', {"KeyId": ecc_signing_key['KeyId']})
        assert code == 400
        assert resp['__type'] == 'UnsupportedOperationException'

    def test_external_key_returns_unsupported_operation(self, kms_client):
        """GetKeyRotationStatus on an EXTERNAL origin key must return UnsupportedOperationException."""
        _, resp = kms_client.post('CreateKey', {"Origin": "EXTERNAL"})
        key_id = resp['KeyMetadata']['KeyId']

        code, content = kms_client.post('GetKeyRotationStatus', {"KeyId": key_id})
        assert code == 400
        assert content['__type'] == 'UnsupportedOperationException'


class TestEnableDisableKeyRotation:

    def test_enable_rotation_rsa_fails(self, kms_client, rsa_signing_key):
        """EnableKeyRotation on RSA key must return UnsupportedOperationException."""
        code, resp = kms_client.post('EnableKeyRotation', {"KeyId": rsa_signing_key['KeyId']})
        assert code == 400
        assert resp['__type'] == 'UnsupportedOperationException'

    def test_enable_rotation_ecc_fails(self, kms_client, ecc_signing_key):
        """EnableKeyRotation on ECC key must return UnsupportedOperationException."""
        code, resp = kms_client.post('EnableKeyRotation', {"KeyId": ecc_signing_key['KeyId']})
        assert code == 400
        assert resp['__type'] == 'UnsupportedOperationException'

    def test_disable_rotation_rsa_fails(self, kms_client, rsa_signing_key):
        """DisableKeyRotation on RSA key must return UnsupportedOperationException."""
        code, resp = kms_client.post('DisableKeyRotation', {"KeyId": rsa_signing_key['KeyId']})
        assert code == 400
        assert resp['__type'] == 'UnsupportedOperationException'

    def test_disable_rotation_ecc_fails(self, kms_client, ecc_signing_key):
        """DisableKeyRotation on ECC key must return UnsupportedOperationException."""
        code, resp = kms_client.post('DisableKeyRotation', {"KeyId": ecc_signing_key['KeyId']})
        assert code == 400
        assert resp['__type'] == 'UnsupportedOperationException'

    def test_enable_rotation_with_alias_fails(self, kms_client, symmetric_key):
        """EnableKeyRotation does not resolve aliases; alias name as KeyId must return NotFoundException."""
        alias = f"alias/rotation-alias-{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias})

        code, content = kms_client.post('EnableKeyRotation', {"KeyId": alias})
        assert code == 400
        assert content['__type'] == 'NotFoundException'

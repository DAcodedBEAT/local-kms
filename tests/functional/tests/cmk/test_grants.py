"""
Tests for CreateGrant, ListGrants, ListRetirableGrants, RevokeGrant, RetireGrant.
"""
from uuid import uuid4

from tests.helpers import assert_error_response


def _role_arn(name):
    return f"arn:aws:iam::111122223333:role/{name}"


class TestCreateGrant:

    def test_create_grant_returns_id_and_token(self, kms_client, symmetric_key):
        code, content = kms_client.post('CreateGrant', {
            "KeyId": symmetric_key['KeyId'],
            "GranteePrincipal": _role_arn(f"grantee-{uuid4()}"),
            "Operations": ["Encrypt", "Decrypt"],
        })
        assert code == 200
        assert content['GrantId']
        assert content['GrantToken']

    def test_missing_operations_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post('CreateGrant', {
            "KeyId": symmetric_key['KeyId'],
            "GranteePrincipal": _role_arn(f"grantee-{uuid4()}"),
        })
        assert code == 400
        assert_error_response(content, 'MissingParameterException')

    def test_missing_grantee_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post('CreateGrant', {
            "KeyId": symmetric_key['KeyId'],
            "Operations": ["Encrypt"],
        })
        assert code == 400
        assert_error_response(content, 'ValidationException')

    def test_nonexistent_key_fails(self, kms_client):
        code, content = kms_client.post('CreateGrant', {
            "KeyId": "arn:aws:kms:eu-west-2:111122223333:key/00000000-1111-2222-3333-444444444444",
            "GranteePrincipal": _role_arn(f"grantee-{uuid4()}"),
            "Operations": ["Encrypt"],
        })
        assert code == 400
        assert_error_response(content, 'NotFoundException')


class TestListGrants:

    def test_lists_created_grant(self, kms_client, symmetric_key):
        key_id = symmetric_key['KeyId']
        code, grant = kms_client.post('CreateGrant', {
            "KeyId": key_id,
            "GranteePrincipal": _role_arn(f"grantee-{uuid4()}"),
            "Operations": ["Encrypt", "Decrypt"],
        })
        assert code == 200

        code, content = kms_client.post('ListGrants', {"KeyId": key_id})
        assert code == 200
        grant_ids = [g['GrantId'] for g in content['Grants']]
        assert grant['GrantId'] in grant_ids

    def test_filters_by_grant_id(self, kms_client, symmetric_key):
        key_id = symmetric_key['KeyId']
        _, grant_a = kms_client.post('CreateGrant', {
            "KeyId": key_id,
            "GranteePrincipal": _role_arn(f"grantee-{uuid4()}"),
            "Operations": ["Encrypt"],
        })
        kms_client.post('CreateGrant', {
            "KeyId": key_id,
            "GranteePrincipal": _role_arn(f"grantee-{uuid4()}"),
            "Operations": ["Decrypt"],
        })

        code, content = kms_client.post('ListGrants', {"KeyId": key_id, "GrantId": grant_a['GrantId']})
        assert code == 200
        assert len(content['Grants']) == 1
        assert content['Grants'][0]['GrantId'] == grant_a['GrantId']


class TestRevokeGrant:

    def test_revoke_removes_grant(self, kms_client, symmetric_key):
        key_id = symmetric_key['KeyId']
        _, grant = kms_client.post('CreateGrant', {
            "KeyId": key_id,
            "GranteePrincipal": _role_arn(f"grantee-{uuid4()}"),
            "Operations": ["Encrypt"],
        })

        code, unused = kms_client.post('RevokeGrant', {"KeyId": key_id, "GrantId": grant['GrantId']})
        assert code == 200

        code, content = kms_client.post('ListGrants', {"KeyId": key_id, "GrantId": grant['GrantId']})
        assert code == 200
        assert content['Grants'] == []

    def test_revoke_nonexistent_grant_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post('RevokeGrant', {
            "KeyId": symmetric_key['KeyId'],
            "GrantId": "0" * 64,
        })
        assert code == 400
        assert_error_response(content, 'NotFoundException')


class TestRetireGrant:

    def test_retire_by_token(self, kms_client, symmetric_key):
        key_id = symmetric_key['KeyId']
        _, grant = kms_client.post('CreateGrant', {
            "KeyId": key_id,
            "GranteePrincipal": _role_arn(f"grantee-{uuid4()}"),
            "Operations": ["Encrypt"],
        })

        code, unused = kms_client.post('RetireGrant', {"GrantToken": grant['GrantToken']})
        assert code == 200

        code, content = kms_client.post('ListGrants', {"KeyId": key_id, "GrantId": grant['GrantId']})
        assert code == 200
        assert content['Grants'] == []

    def test_retire_by_key_and_grant_id(self, kms_client, symmetric_key):
        key_id = symmetric_key['KeyId']
        _, grant = kms_client.post('CreateGrant', {
            "KeyId": key_id,
            "GranteePrincipal": _role_arn(f"grantee-{uuid4()}"),
            "Operations": ["Encrypt"],
        })

        code, unused = kms_client.post('RetireGrant', {"KeyId": key_id, "GrantId": grant['GrantId']})
        assert code == 200

        code, content = kms_client.post('ListGrants', {"KeyId": key_id, "GrantId": grant['GrantId']})
        assert code == 200
        assert content['Grants'] == []

    def test_retire_missing_identifiers_fails(self, kms_client):
        code, content = kms_client.post('RetireGrant', {})
        assert code == 400
        assert_error_response(content, 'ValidationException')


class TestListRetirableGrants:

    def test_filters_by_retiring_principal(self, kms_client, symmetric_key):
        key_id = symmetric_key['KeyId']
        retiree = _role_arn(f"retiree-{uuid4()}")

        _, grant = kms_client.post('CreateGrant', {
            "KeyId": key_id,
            "GranteePrincipal": _role_arn(f"grantee-{uuid4()}"),
            "RetiringPrincipal": retiree,
            "Operations": ["Encrypt"],
        })
        kms_client.post('CreateGrant', {
            "KeyId": key_id,
            "GranteePrincipal": _role_arn(f"grantee-{uuid4()}"),
            "RetiringPrincipal": _role_arn(f"other-{uuid4()}"),
            "Operations": ["Decrypt"],
        })

        code, content = kms_client.post('ListRetirableGrants', {"RetiringPrincipal": retiree})
        assert code == 200
        grant_ids = [g['GrantId'] for g in content['Grants']]
        assert grant['GrantId'] in grant_ids
        assert len(grant_ids) == 1

    def test_missing_retiring_principal_fails(self, kms_client):
        code, content = kms_client.post('ListRetirableGrants', {})
        assert code == 400
        assert_error_response(content, 'MissingParameterException')

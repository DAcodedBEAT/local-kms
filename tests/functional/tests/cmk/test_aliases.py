import base64
import pytest
from uuid import uuid4


_HELLO_WORLD_B64 = base64.b64encode(b"Hello World").decode()


class TestAliasBasicOperations:

    def test_symmetric_key_alias(self, kms_client, symmetric_key):
        alias_name = f"alias/{uuid4()}"

        code, _ = kms_client.post('CreateAlias', {
            "TargetKeyId": symmetric_key['Arn'],
            "AliasName": alias_name,
        })
        assert code == 200

        code, enc = kms_client.post('Encrypt', {
            "KeyId": alias_name, "Plaintext": _HELLO_WORLD_B64,
        })
        assert code == 200

        code, dec = kms_client.post('Decrypt', {"CiphertextBlob": enc['CiphertextBlob']})
        assert code == 200
        assert dec['Plaintext'] == _HELLO_WORLD_B64

    def test_rsa_encryption_alias(self, kms_client, rsa_encryption_key):
        alias_name = f"alias/{uuid4()}"

        code, _ = kms_client.post('CreateAlias', {
            "TargetKeyId": rsa_encryption_key['Arn'],
            "AliasName": alias_name,
        })
        assert code == 200

        code, enc = kms_client.post('Encrypt', {
            "KeyId": alias_name,
            "EncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            "Plaintext": _HELLO_WORLD_B64,
        })
        assert code == 200

        code, dec = kms_client.post('Decrypt', {
            "KeyId": alias_name,
            "EncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            "CiphertextBlob": enc['CiphertextBlob'],
        })
        assert code == 200
        assert dec['Plaintext'] == _HELLO_WORLD_B64

    def test_rsa_signing_alias(self, kms_client, rsa_signing_key):
        alias_name = f"alias/{uuid4()}"

        code, _ = kms_client.post('CreateAlias', {
            "TargetKeyId": rsa_signing_key['Arn'],
            "AliasName": alias_name,
        })
        assert code == 200

        code, signed = kms_client.post('Sign', {
            "KeyId": alias_name,
            "Message": _HELLO_WORLD_B64,
            "MessageType": "RAW",
            "SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
        })
        assert code == 200

        code, verified = kms_client.post('Verify', {
            "KeyId": alias_name,
            "Message": _HELLO_WORLD_B64,
            "MessageType": "RAW",
            "SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
            "Signature": signed['Signature'],
        })
        assert code == 200
        assert verified['SignatureValid'] is True


class TestAliasNaming:

    def test_missing_alias_prefix_fails(self, kms_client, symmetric_key):
        """AliasName must start with 'alias/'; bare names must be rejected with InvalidAliasNameException."""
        code, content = kms_client.post('CreateAlias', {
            "TargetKeyId": symmetric_key['KeyId'],
            "AliasName": "no-prefix-here",
        })
        assert code == 400
        assert content["__type"] == "InvalidAliasNameException"

    def test_reserved_aws_prefix_fails(self, kms_client, symmetric_key):
        """'alias/aws/' prefix is reserved; local-kms returns NotAuthorizedException."""
        code, content = kms_client.post('CreateAlias', {
            "TargetKeyId": symmetric_key['KeyId'],
            "AliasName": "alias/aws/reserved",
        })
        assert code == 400
        assert content["__type"] == "NotAuthorizedException"

    def test_alias_starting_with_aws_no_slash_is_valid(self, kms_client, symmetric_key):
        """alias/awesome is NOT reserved — only alias/aws/ (with slash) is reserved."""
        alias = f"alias/awesome-{uuid4()}"
        code, _ = kms_client.post('CreateAlias', {
            "TargetKeyId": symmetric_key['KeyId'],
            "AliasName": alias,
        })
        assert code == 200

    def test_invalid_alias_characters_fails(self, kms_client, symmetric_key):
        """Alias names with invalid characters must return InvalidAliasNameException."""
        code, content = kms_client.post('CreateAlias', {
            "TargetKeyId": symmetric_key['KeyId'],
            "AliasName": "alias/invalid name!",
        })
        assert code == 400
        assert content["__type"] == "InvalidAliasNameException"

    def test_alias_for_nonexistent_key_fails(self, kms_client):
        """Creating an alias for a key that does not exist must fail."""
        code, content = kms_client.post('CreateAlias', {
            "TargetKeyId": str(uuid4()),
            "AliasName": f"alias/{uuid4()}",
        })
        assert code == 400
        assert content["__type"] == "NotFoundException"

    def test_delete_nonexistent_alias_fails(self, kms_client):
        code, content = kms_client.post('DeleteAlias', {"AliasName": f"alias/{uuid4()}"})
        assert code == 400
        assert content["__type"] == "NotFoundException"

    def test_delete_alias_starting_with_aws_no_slash_is_valid(self, kms_client, symmetric_key):
        """alias/awesome is NOT reserved — only alias/aws/ (with slash) is blocked on delete."""
        alias = f"alias/awesome-{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias})
        code, _ = kms_client.post('DeleteAlias', {"AliasName": alias})
        assert code == 200

    def test_delete_reserved_aws_prefix_fails(self, kms_client, symmetric_key):
        """DeleteAlias on alias/aws/... must return KMSInvalidStateException."""
        code, content = kms_client.post('DeleteAlias', {"AliasName": "alias/aws/reserved"})
        assert code == 400
        assert content["__type"] == "KMSInvalidStateException"

    def test_delete_alias_without_alias_prefix_fails(self, kms_client):
        """DeleteAlias AliasName must begin with 'alias/'; bare names must be rejected.
        Docs list no InvalidAliasNameException for DeleteAlias — ValidationException is the
        expected common-error response.
        """
        code, content = kms_client.post('DeleteAlias', {"AliasName": "wrongprefix/my-alias"})
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_update_nonexistent_alias_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post('UpdateAlias', {
            "AliasName": f"alias/{uuid4()}",
            "TargetKeyId": symmetric_key['KeyId'],
        })
        assert code == 400
        assert content["__type"] == "NotFoundException"

    def test_create_alias_on_pending_deletion_key_fails(self, kms_client):
        """CreateAlias on a key scheduled for deletion must return KMSInvalidStateException."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        kms_client.post('ScheduleKeyDeletion', {'KeyId': key_id, 'PendingWindowInDays': 7})

        code, content = kms_client.post('CreateAlias', {
            "TargetKeyId": key_id,
            "AliasName": f"alias/{uuid4()}",
        })
        assert code == 400
        assert content["__type"] == "KMSInvalidStateException"

    def test_update_alias_different_key_usage_fails(self, kms_client, symmetric_key, rsa_signing_key):
        """UpdateAlias retargeting to a key with different KeyUsage must fail."""
        alias = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias})

        code, content = kms_client.post('UpdateAlias', {
            "AliasName": alias,
            "TargetKeyId": rsa_signing_key['KeyId'],
        })
        assert code == 400

    def test_update_alias_different_key_type_fails(self, kms_client, rsa_signing_key, ecc_signing_key):
        """UpdateAlias retargeting to a different key type (RSA→ECC) must fail."""
        alias = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": rsa_signing_key['KeyId'], "AliasName": alias})

        code, content = kms_client.post('UpdateAlias', {
            "AliasName": alias,
            "TargetKeyId": ecc_signing_key['KeyId'],
        })
        assert code == 400

    def test_update_alias_to_pending_deletion_key_fails(self, kms_client, symmetric_key):
        """UpdateAlias targeting a key pending deletion must return KMSInvalidStateException."""
        alias = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias})

        _, resp = kms_client.post('CreateKey', {})
        target_id = resp['KeyMetadata']['KeyId']
        kms_client.post('ScheduleKeyDeletion', {'KeyId': target_id, 'PendingWindowInDays': 7})

        code, content = kms_client.post('UpdateAlias', {
            "AliasName": alias,
            "TargetKeyId": target_id,
        })
        assert code == 400
        assert content["__type"] == "KMSInvalidStateException"

    def test_create_alias_duplicate_fails(self, kms_client, symmetric_key):
        """Creating an alias name that already exists must return AlreadyExistsException."""
        alias_name = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias_name})

        code, content = kms_client.post('CreateAlias', {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias_name})
        assert code == 400
        assert content["__type"] == "AlreadyExistsException"

    def test_create_alias_with_alias_as_target_fails(self, kms_client, symmetric_key):
        """TargetKeyId must be a key ID or ARN, not an alias name.
        AWS returns ValidationException('Aliases must refer to keys. Not aliases').
        """
        alias = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias})

        code, content = kms_client.post('CreateAlias', {
            "TargetKeyId": alias,
            "AliasName": f"alias/{uuid4()}",
        })
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_create_alias_with_colon_in_name_fails(self, kms_client, symmetric_key):
        """Colon is not in the allowed alias character set; must be rejected."""
        code, content = kms_client.post('CreateAlias', {
            "TargetKeyId": symmetric_key['KeyId'],
            "AliasName": "alias/invalid:name",
        })
        assert code == 400
        assert content["__type"] == "InvalidAliasNameException"


class TestUpdateAlias:

    def test_update_alias_same_target_via_arn_succeeds(self, kms_client, symmetric_key):
        """UpdateAlias pointing to the same key via ARN (no-op) must succeed."""
        alias = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias})

        code, _ = kms_client.post('UpdateAlias', {
            "AliasName": alias,
            "TargetKeyId": symmetric_key['Arn'],
        })
        assert code == 200

        code, content = kms_client.post('ListAliases', {"KeyId": symmetric_key['KeyId']})
        assert code == 200
        assert any(a['AliasName'] == alias for a in content['Aliases'])

    def test_update_alias_changes_target_key(self, kms_client, symmetric_key):
        """UpdateAlias retargets alias; ListAliases filtered by new key reflects the change."""
        alias_name = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias_name})

        _, resp = kms_client.post('CreateKey', {})
        second_key = resp['KeyMetadata']

        code, _ = kms_client.post('UpdateAlias', {"AliasName": alias_name, "TargetKeyId": second_key['KeyId']})
        assert code == 200

        code, content = kms_client.post('ListAliases', {"KeyId": second_key['KeyId']})
        assert code == 200
        aliases = [a for a in content['Aliases'] if a['AliasName'] == alias_name]
        assert len(aliases) == 1
        assert aliases[0]['TargetKeyId'] == second_key['KeyId']

    def test_delete_alias_no_longer_in_list(self, kms_client, symmetric_key):
        """Deleted alias must not appear in ListAliases filtered by key."""
        alias_name = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias_name})

        code, _ = kms_client.post('DeleteAlias', {"AliasName": alias_name})
        assert code == 200

        code, content = kms_client.post('ListAliases', {"KeyId": symmetric_key['KeyId']})
        assert code == 200
        names = [a['AliasName'] for a in content.get('Aliases', [])]
        assert alias_name not in names


class TestListAliases:

    def test_list_aliases_includes_created_alias(self, kms_client, symmetric_key):
        alias = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias})

        # Filter by key to avoid pagination — unfiltered ListAliases has a default page limit
        code, content = kms_client.post('ListAliases', {"KeyId": symmetric_key['KeyId']})
        assert code == 200
        assert "Aliases" in content
        names = [a['AliasName'] for a in content['Aliases']]
        assert alias in names

    def test_list_aliases_by_key_id(self, kms_client, symmetric_key):
        alias = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias})

        code, content = kms_client.post('ListAliases', {"KeyId": symmetric_key['KeyId']})
        assert code == 200
        names = [a['AliasName'] for a in content['Aliases']]
        assert alias in names
        # All returned aliases should target this key
        for a in content['Aliases']:
            assert a.get('TargetKeyId') == symmetric_key['KeyId']

    def test_list_aliases_entry_has_creation_and_update_dates(self, kms_client, symmetric_key):
        """Each AliasListEntry must include CreationDate and LastUpdatedDate."""
        alias = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": symmetric_key['KeyId'], "AliasName": alias})

        _, content = kms_client.post('ListAliases', {"KeyId": symmetric_key['KeyId']})
        entry = next(a for a in content['Aliases'] if a['AliasName'] == alias)
        assert 'CreationDate' in entry, "CreationDate missing from AliasListEntry"
        assert 'LastUpdatedDate' in entry, "LastUpdatedDate missing from AliasListEntry"
        assert isinstance(entry['CreationDate'], (int, float))
        assert isinstance(entry['LastUpdatedDate'], (int, float))

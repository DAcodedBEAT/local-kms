from uuid import uuid4

import pytest

from tests import assert_error_response


class TestKeyManagement:
    def test_create_key_failure_key_usage(self, kms_client):
        code, content = kms_client.post(
            'CreateKey',
            {
                "KeyUsage": "SIGN_VERIFY",
            },
        )

        assert code == 400
        # SIGN_VERIFY is not valid for symmetric keys
        assert_error_response(
            content,
            'ValidationException',
            'The operation failed because the KeyUsage value of the CMK is SIGN_VERIFY. To perform this operation, the KeyUsage value must be ENCRYPT_DECRYPT.',
        )

    def test_create_key_failure_duplicate_spec(self, kms_client):
        code, content = kms_client.post(
            'CreateKey',
            {
                "KeySpec": 'RSA_2048',
                "CustomerMasterKeySpec": 'RSA_2048',
                "KeyUsage": 'ENCRYPT_DECRYPT',
            },
        )

        assert code == 400
        assert_error_response(
            content,
            'ValidationException',
            'You cannot specify KeySpec and CustomerMasterKeySpec in the same request. CustomerMasterKeySpec is deprecated.',
        )

    @pytest.mark.parametrize(
        "key_spec_and_usage",
        [
            ('SYMMETRIC_DEFAULT', 'ENCRYPT_DECRYPT'),
            ('RSA_2048', 'ENCRYPT_DECRYPT'),
            ('RSA_3072', 'ENCRYPT_DECRYPT'),
            ('RSA_4096', 'ENCRYPT_DECRYPT'),
            ('RSA_2048', 'SIGN_VERIFY'),
            ('RSA_3072', 'SIGN_VERIFY'),
            ('RSA_4096', 'SIGN_VERIFY'),
            ('ECC_NIST_P256', 'SIGN_VERIFY'),
            ('ECC_NIST_P384', 'SIGN_VERIFY'),
            ('ECC_NIST_P521', 'SIGN_VERIFY'),
            ('ECC_SECG_P256K1', 'SIGN_VERIFY'),
        ],
    )
    def test_create_key_success_keyspec(self, kms_client, key_spec_and_usage):
        payload = {
            "KeySpec": key_spec_and_usage[0],
            "KeyUsage": key_spec_and_usage[1],
            "Origin": "AWS_KMS",
            "Description": "Test Description",
            "Tags": [
                {
                    "TagKey": "key_spec_and_usage",
                    "TagValue": "%s with %s" % key_spec_and_usage,
                },
            ],
        }

        code, cmk = kms_client.post('CreateKey', payload)
        assert code == 200

        assert isinstance(cmk, dict)
        assert 'KeyMetadata' in cmk

        key_metadata = cmk['KeyMetadata']

        assert {
            'AWSAccountId',
            'Arn',
            'CreationDate',
            'KeySpec',
            'CustomerMasterKeySpec',
            'Description',
            'Enabled',
            'KeyId',
            'KeyManager',
            'KeyState',
            'KeyUsage',
            'MultiRegion',
            'Origin',
        }.issubset(set(key_metadata.keys()))

        assert payload['KeySpec'] == key_metadata['KeySpec']
        assert payload['KeySpec'] == key_metadata['CustomerMasterKeySpec']
        assert payload['KeyUsage'] == key_metadata['KeyUsage']
        assert payload['Origin'] == key_metadata['Origin']
        assert payload['Description'] == key_metadata['Description']

        # ---

        code, description = kms_client.post(
            'DescribeKey', {"KeyId": key_metadata['Arn']}
        )
        assert code == 200
        assert (
            cmk == description
        )  # The description should exactly match the original key

        # ---

        code, tags = kms_client.post('ListResourceTags', {"KeyId": key_metadata['Arn']})
        assert code == 200
        assert isinstance(tags, dict)
        assert tags['Truncated'] is False
        assert payload['Tags'] == tags['Tags']

        # ---

        code, delete = kms_client.post(
            'ScheduleKeyDeletion',
            {'KeyId': cmk['KeyMetadata']['KeyId'], 'PendingWindowInDays': 7},
        )

        assert code == 200
        assert isinstance(delete, dict)
        assert cmk['KeyMetadata']['Arn'] == delete['KeyId']
        assert isinstance(delete['DeletionDate'], float)
        assert delete['KeyState'] == 'PendingDeletion'
        assert delete['PendingWindowInDays'] == 7

    def test_create_key_multiregion_always_false(self, kms_client):
        """CreateKey always returns MultiRegion=false (local-kms is single-region only)."""
        code, cmk = kms_client.post('CreateKey', {})
        assert code == 200
        assert cmk['KeyMetadata']['MultiRegion'] is False

    def test_create_key_default_description_is_empty_string(self, kms_client):
        """When Description is omitted, the response must contain Description='' not null."""
        code, cmk = kms_client.post('CreateKey', {})
        assert code == 200
        meta = cmk['KeyMetadata']
        assert 'Description' in meta
        assert meta['Description'] == ""

    def test_create_key_success_customermasterkeyspec(self, kms_client):
        """
        Check once using the now deprecated CustomerMasterKeySpec.
        AWS are still supporting this.
        """

        key_spec_and_usage = ('SYMMETRIC_DEFAULT', 'ENCRYPT_DECRYPT')

        payload = {
            "CustomerMasterKeySpec": key_spec_and_usage[0],
            "KeyUsage": key_spec_and_usage[1],
            "Origin": "AWS_KMS",
            "Description": "Test Description",
            "Tags": [
                {
                    "TagKey": "key_spec_and_usage",
                    "TagValue": "%s with %s" % key_spec_and_usage,
                },
            ],
        }

        code, cmk = kms_client.post('CreateKey', payload)
        assert code == 200

        assert isinstance(cmk, dict)
        assert 'KeyMetadata' in cmk

        key_metadata = cmk['KeyMetadata']

        assert {
            'AWSAccountId',
            'Arn',
            'CreationDate',
            'KeySpec',
            'CustomerMasterKeySpec',
            'Description',
            'Enabled',
            'KeyId',
            'KeyManager',
            'KeyState',
            'KeyUsage',
            'MultiRegion',
            'Origin',
        }.issubset(set(key_metadata.keys()))

        assert payload['CustomerMasterKeySpec'] == key_metadata['KeySpec']
        assert payload['CustomerMasterKeySpec'] == key_metadata['CustomerMasterKeySpec']
        assert payload['KeyUsage'] == key_metadata['KeyUsage']
        assert payload['Origin'] == key_metadata['Origin']
        assert payload['Description'] == key_metadata['Description']

        # ---

        code, description = kms_client.post(
            'DescribeKey', {"KeyId": key_metadata['Arn']}
        )
        assert code == 200
        assert (
            cmk == description
        )  # The description should exactly match the original key

        # ---

        code, tags = kms_client.post('ListResourceTags', {"KeyId": key_metadata['Arn']})
        assert code == 200
        assert isinstance(tags, dict)
        assert tags['Truncated'] is False
        assert payload['Tags'] == tags['Tags']

        # ---

        code, delete = kms_client.post(
            'ScheduleKeyDeletion',
            {'KeyId': cmk['KeyMetadata']['KeyId'], 'PendingWindowInDays': 7},
        )

        assert code == 200
        assert isinstance(delete, dict)
        assert cmk['KeyMetadata']['Arn'] == delete['KeyId']
        assert isinstance(delete['DeletionDate'], float)
        assert delete['KeyState'] == 'PendingDeletion'
        assert delete['PendingWindowInDays'] == 7


class TestEnableKey:

    def test_enable_disabled_key_succeeds(self, kms_client):
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        kms_client.post('DisableKey', {"KeyId": key_id})

        code, _ = kms_client.post('EnableKey', {"KeyId": key_id})
        assert code == 200

        _, desc = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert desc['KeyMetadata']['KeyState'] == 'Enabled'
        assert desc['KeyMetadata']['Enabled'] is True

    def test_enable_via_arn(self, kms_client):
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        key_arn = resp['KeyMetadata']['Arn']
        kms_client.post('DisableKey', {"KeyId": key_id})

        code, _ = kms_client.post('EnableKey', {"KeyId": key_arn})
        assert code == 200

    def test_enable_idempotent(self, kms_client):
        """Enabling an already-enabled key must succeed (idempotent)."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, _ = kms_client.post('EnableKey', {"KeyId": key_id})
        assert code == 200

    def test_enable_missing_key_id_fails(self, kms_client):
        code, content = kms_client.post('EnableKey', {})
        assert code == 400
        assert content['__type'] == 'MissingParameterException'

    def test_enable_nonexistent_key_fails(self, kms_client):
        code, content = kms_client.post('EnableKey', {"KeyId": str(uuid4())})
        assert code == 400
        assert content['__type'] == 'NotFoundException'

    def test_enable_pending_deletion_fails(self, kms_client):
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        kms_client.post('ScheduleKeyDeletion', {"KeyId": key_id, "PendingWindowInDays": 7})

        code, content = kms_client.post('EnableKey', {"KeyId": key_id})
        assert code == 400
        assert content['__type'] == 'KMSInvalidStateException'

    def test_enable_pending_import_fails(self, kms_client):
        _, resp = kms_client.post('CreateKey', {"Origin": "EXTERNAL"})
        key_id = resp['KeyMetadata']['KeyId']

        code, content = kms_client.post('EnableKey', {"KeyId": key_id})
        assert code == 400
        assert content['__type'] == 'KMSInvalidStateException'


class TestDisableKey:

    def test_disable_enabled_key_succeeds(self, kms_client):
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, _ = kms_client.post('DisableKey', {"KeyId": key_id})
        assert code == 200

        _, desc = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert desc['KeyMetadata']['KeyState'] == 'Disabled'
        assert desc['KeyMetadata']['Enabled'] is False

    def test_disable_via_alias(self, kms_client):
        """DisableKey resolves aliases via getKey."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        alias = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": key_id, "AliasName": alias})

        code, _ = kms_client.post('DisableKey', {"KeyId": alias})
        assert code == 200

        _, desc = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert desc['KeyMetadata']['KeyState'] == 'Disabled'

    def test_disable_idempotent(self, kms_client):
        """Disabling an already-disabled key must succeed (idempotent)."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        kms_client.post('DisableKey', {"KeyId": key_id})

        code, _ = kms_client.post('DisableKey', {"KeyId": key_id})
        assert code == 200

    def test_disable_missing_key_id_fails(self, kms_client):
        code, content = kms_client.post('DisableKey', {})
        assert code == 400
        assert content['__type'] == 'MissingParameterException'

    def test_disable_nonexistent_key_fails(self, kms_client):
        code, content = kms_client.post('DisableKey', {"KeyId": str(uuid4())})
        assert code == 400
        assert content['__type'] == 'NotFoundException'

    def test_disable_pending_deletion_fails(self, kms_client):
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        kms_client.post('ScheduleKeyDeletion', {"KeyId": key_id, "PendingWindowInDays": 7})

        code, content = kms_client.post('DisableKey', {"KeyId": key_id})
        assert code == 400
        assert content['__type'] == 'KMSInvalidStateException'

    def test_disable_pending_import_fails(self, kms_client):
        _, resp = kms_client.post('CreateKey', {"Origin": "EXTERNAL"})
        key_id = resp['KeyMetadata']['KeyId']

        code, content = kms_client.post('DisableKey', {"KeyId": key_id})
        assert code == 400
        assert content['__type'] == 'KMSInvalidStateException'

    def test_disable_then_enable_roundtrip(self, kms_client):
        """Disable then enable restores Enabled state."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        kms_client.post('DisableKey', {"KeyId": key_id})
        kms_client.post('EnableKey', {"KeyId": key_id})

        _, desc = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert desc['KeyMetadata']['KeyState'] == 'Enabled'


class TestCreateKeyValidation:

    def test_external_origin_with_rsa_keyspec_fails(self, kms_client):
        """Origin=EXTERNAL is only valid for SYMMETRIC_DEFAULT; RSA must be rejected."""
        code, content = kms_client.post('CreateKey', {
            "Origin": "EXTERNAL",
            "KeySpec": "RSA_2048",
            "KeyUsage": "ENCRYPT_DECRYPT",
        })
        assert code == 400
        assert content['__type'] == 'ValidationException'

    def test_cloudhsm_origin_returns_unsupported(self, kms_client):
        """Origin=AWS_CLOUDHSM is not implemented; must return UnsupportedOperationException."""
        code, content = kms_client.post('CreateKey', {"Origin": "AWS_CLOUDHSM"})
        assert code == 400
        assert content['__type'] == 'UnsupportedOperationException'

    def test_invalid_origin_fails(self, kms_client):
        """Unknown Origin value must return ValidationException."""
        code, content = kms_client.post('CreateKey', {"Origin": "BOGUS_ORIGIN"})
        assert code == 400
        assert content['__type'] == 'ValidationException'

    def test_invalid_key_spec_fails(self, kms_client):
        """Unknown KeySpec value must return ValidationException."""
        code, content = kms_client.post('CreateKey', {
            "KeySpec": "INVALID_SPEC",
            "KeyUsage": "SIGN_VERIFY",
        })
        assert code == 400
        assert content['__type'] == 'ValidationException'

    def test_ecc_key_without_key_usage_fails(self, kms_client):
        """ECC key requires explicit KeyUsage; omitting it must return ValidationException."""
        code, content = kms_client.post('CreateKey', {"KeySpec": "ECC_NIST_P256"})
        assert code == 400
        assert content['__type'] == 'ValidationException'

    def test_ecc_key_with_encrypt_decrypt_usage_fails(self, kms_client):
        """ECC keys only support SIGN_VERIFY; ENCRYPT_DECRYPT must be rejected."""
        code, content = kms_client.post('CreateKey', {
            "KeySpec": "ECC_NIST_P256",
            "KeyUsage": "ENCRYPT_DECRYPT",
        })
        assert code == 400
        assert content['__type'] == 'ValidationException'

    def test_rsa_key_without_key_usage_fails(self, kms_client):
        """RSA key requires explicit KeyUsage; omitting it must return ValidationException."""
        code, content = kms_client.post('CreateKey', {"KeySpec": "RSA_2048"})
        assert code == 400
        assert content['__type'] == 'ValidationException'

    def test_rsa_key_with_invalid_usage_fails(self, kms_client):
        """RSA only supports ENCRYPT_DECRYPT or SIGN_VERIFY; other values must fail."""
        code, content = kms_client.post('CreateKey', {
            "KeySpec": "RSA_2048",
            "KeyUsage": "GENERATE_VERIFY_MAC",
        })
        assert code == 400
        assert content['__type'] == 'ValidationException'

    def test_description_too_long_fails(self, kms_client):
        """Description > 8192 chars must return ValidationException."""
        code, content = kms_client.post('CreateKey', {"Description": "x" * 8193})
        assert code == 400
        assert content['__type'] == 'ValidationException'


class TestCreateKeyResponseFields:

    def test_symmetric_key_has_encryption_algorithms(self, kms_client):
        """Symmetric key response must include EncryptionAlgorithms: ['SYMMETRIC_DEFAULT']."""
        code, resp = kms_client.post('CreateKey', {})
        assert code == 200
        meta = resp['KeyMetadata']
        assert meta.get('EncryptionAlgorithms') == ['SYMMETRIC_DEFAULT']

    def test_rsa_signing_key_has_signing_algorithms(self, kms_client):
        """RSA SIGN_VERIFY key must list all 6 RSA signing algorithms."""
        code, resp = kms_client.post('CreateKey', {
            "KeySpec": "RSA_2048",
            "KeyUsage": "SIGN_VERIFY",
        })
        assert code == 200
        algos = resp['KeyMetadata'].get('SigningAlgorithms', [])
        assert set(algos) == {
            'RSASSA_PSS_SHA_256', 'RSASSA_PSS_SHA_384', 'RSASSA_PSS_SHA_512',
            'RSASSA_PKCS1_V1_5_SHA_256', 'RSASSA_PKCS1_V1_5_SHA_384', 'RSASSA_PKCS1_V1_5_SHA_512',
        }
        assert 'EncryptionAlgorithms' not in resp['KeyMetadata']

    def test_rsa_encryption_key_has_encryption_algorithms(self, kms_client):
        """RSA ENCRYPT_DECRYPT key must list RSAES_OAEP_SHA_1 and RSAES_OAEP_SHA_256."""
        code, resp = kms_client.post('CreateKey', {
            "KeySpec": "RSA_2048",
            "KeyUsage": "ENCRYPT_DECRYPT",
        })
        assert code == 200
        algos = resp['KeyMetadata'].get('EncryptionAlgorithms', [])
        assert set(algos) == {'RSAES_OAEP_SHA_1', 'RSAES_OAEP_SHA_256'}
        assert 'SigningAlgorithms' not in resp['KeyMetadata']

    @pytest.mark.parametrize("key_spec,expected_algo", [
        ('ECC_NIST_P256', 'ECDSA_SHA_256'),
        ('ECC_NIST_P384', 'ECDSA_SHA_384'),
        ('ECC_NIST_P521', 'ECDSA_SHA_512'),
        ('ECC_SECG_P256K1', 'ECDSA_SHA_256'),
    ])
    def test_ecc_key_has_correct_signing_algorithm(self, kms_client, key_spec, expected_algo):
        """Each ECC spec must return exactly one signing algorithm in the response."""
        code, resp = kms_client.post('CreateKey', {
            "KeySpec": key_spec,
            "KeyUsage": "SIGN_VERIFY",
        })
        assert code == 200
        algos = resp['KeyMetadata'].get('SigningAlgorithms', [])
        assert algos == [expected_algo]

    def test_external_origin_key_state_is_pending_import(self, kms_client):
        """EXTERNAL origin key must have KeyState=PendingImport and Enabled=False."""
        code, resp = kms_client.post('CreateKey', {"Origin": "EXTERNAL"})
        assert code == 200
        meta = resp['KeyMetadata']
        assert meta['KeyState'] == 'PendingImport'
        assert meta['Enabled'] is False
        assert meta['Origin'] == 'EXTERNAL'

    def test_creation_date_is_numeric(self, kms_client):
        """CreationDate must be a number (Unix epoch float), not a string."""
        code, resp = kms_client.post('CreateKey', {})
        assert code == 200
        assert isinstance(resp['KeyMetadata']['CreationDate'], (int, float))

    def test_key_manager_is_customer(self, kms_client):
        """Customer-created keys must have KeyManager='CUSTOMER'."""
        code, resp = kms_client.post('CreateKey', {})
        assert code == 200
        assert resp['KeyMetadata']['KeyManager'] == 'CUSTOMER'

    def test_aws_kms_origin_key_is_enabled_by_default(self, kms_client):
        """AWS_KMS origin key must be Enabled=True with KeyState=Enabled."""
        code, resp = kms_client.post('CreateKey', {})
        assert code == 200
        meta = resp['KeyMetadata']
        assert meta['Enabled'] is True
        assert meta['KeyState'] == 'Enabled'


class TestDescribeKey:

    def test_describe_key_nonexistent_alias_fails(self, kms_client):
        """DescribeKey with an alias that has no backing key must return NotFoundException."""
        code, content = kms_client.post('DescribeKey', {"KeyId": f"alias/{uuid4()}"})
        assert code == 400
        assert content['__type'] == 'NotFoundException'

    def test_missing_key_id_fails(self, kms_client):
        code, content = kms_client.post('DescribeKey', {})
        assert code == 400
        assert content['__type'] == 'MissingParameterException'

    def test_nonexistent_key_id_fails(self, kms_client):
        code, content = kms_client.post('DescribeKey', {"KeyId": str(uuid4())})
        assert code == 400
        assert content['__type'] == 'NotFoundException'

    def test_describe_via_arn_succeeds(self, kms_client):
        _, resp = kms_client.post('CreateKey', {})
        key_arn = resp['KeyMetadata']['Arn']
        code, described = kms_client.post('DescribeKey', {"KeyId": key_arn})
        assert code == 200
        assert described['KeyMetadata']['Arn'] == key_arn

    def test_describe_via_alias_succeeds(self, kms_client):
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        key_arn = resp['KeyMetadata']['Arn']
        alias = f"alias/describe-{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": key_id, "AliasName": alias})

        code, described = kms_client.post('DescribeKey', {"KeyId": alias})
        assert code == 200
        assert described['KeyMetadata']['Arn'] == key_arn

    def test_symmetric_key_response_shape(self, kms_client):
        """Symmetric key DescribeKey response must include all mandatory metadata fields."""
        _, resp = kms_client.post('CreateKey', {"Description": "describe-shape-test"})
        key_id = resp['KeyMetadata']['KeyId']

        code, described = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        meta = described['KeyMetadata']
        for field in ('Arn', 'AWSAccountId', 'CreationDate', 'CustomerMasterKeySpec',
                      'Description', 'Enabled', 'KeyId', 'KeyManager', 'KeySpec',
                      'KeyState', 'KeyUsage', 'MultiRegion', 'Origin'):
            assert field in meta, f"Missing field: {field}"
        assert meta['EncryptionAlgorithms'] == ['SYMMETRIC_DEFAULT']
        assert 'SigningAlgorithms' not in meta

    def test_rsa_signing_key_has_signing_algorithms(self, kms_client):
        """RSA SIGN_VERIFY key must have SigningAlgorithms, no EncryptionAlgorithms."""
        _, resp = kms_client.post('CreateKey', {"KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY"})
        key_id = resp['KeyMetadata']['KeyId']

        code, described = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        meta = described['KeyMetadata']
        assert 'SigningAlgorithms' in meta
        assert len(meta['SigningAlgorithms']) == 6
        assert 'EncryptionAlgorithms' not in meta

    def test_customer_master_key_spec_equals_key_spec(self, kms_client):
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        code, described = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        meta = described['KeyMetadata']
        assert meta['CustomerMasterKeySpec'] == meta['KeySpec']

    def test_creation_date_is_numeric(self, kms_client):
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        code, described = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        assert isinstance(described['KeyMetadata']['CreationDate'], (int, float))

    def test_description_preserved(self, kms_client):
        _, resp = kms_client.post('CreateKey', {"Description": "my-test-desc"})
        key_id = resp['KeyMetadata']['KeyId']
        code, described = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        assert described['KeyMetadata']['Description'] == "my-test-desc"

    def test_disabled_key_succeeds(self, kms_client):
        """DescribeKey uses getKey (not getUsableKey); must succeed even on disabled key."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        kms_client.post('DisableKey', {"KeyId": key_id})

        code, described = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        assert described['KeyMetadata']['KeyState'] == 'Disabled'
        assert described['KeyMetadata']['Enabled'] is False

    def test_pending_deletion_key_succeeds_with_deletion_date(self, kms_client):
        """DescribeKey on a pending-deletion key must succeed and include DeletionDate."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        kms_client.post('ScheduleKeyDeletion', {"KeyId": key_id, "PendingWindowInDays": 7})

        code, described = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        meta = described['KeyMetadata']
        assert meta['KeyState'] == 'PendingDeletion'
        assert isinstance(meta.get('DeletionDate'), float)

    def test_pending_import_key_succeeds(self, kms_client):
        """DescribeKey on a PendingImport key must succeed."""
        _, resp = kms_client.post('CreateKey', {"Origin": "EXTERNAL"})
        key_id = resp['KeyMetadata']['KeyId']

        code, described = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        meta = described['KeyMetadata']
        assert meta['KeyState'] == 'PendingImport'
        assert meta['Origin'] == 'EXTERNAL'

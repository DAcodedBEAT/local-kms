import base64
import os
import time
from uuid import uuid4

import pytest
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
from Crypto.Hash import SHA1, SHA256


def _create_external_key(kms_client):
    code, content = kms_client.post('CreateKey', {
        "Origin": "EXTERNAL",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
    })
    assert code == 200
    return content['KeyMetadata']['KeyId']


def _get_import_params(kms_client, key_id, wrapping_algo="RSAES_OAEP_SHA_256"):
    code, params = kms_client.post('GetParametersForImport', {
        "KeyId": key_id,
        "WrappingAlgorithm": wrapping_algo,
        "WrappingKeySpec": "RSA_2048",
    })
    assert code == 200
    return params


def _wrap_key_material(key_material, public_key_b64, wrapping_algo):
    pub_key_der = base64.b64decode(public_key_b64)
    rsa_key = RSA.import_key(pub_key_der)
    if wrapping_algo == "RSAES_OAEP_SHA_256":
        cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    elif wrapping_algo == "RSAES_OAEP_SHA_1":
        cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA1)
    else:
        cipher = PKCS1_v1_5.new(rsa_key)
    return cipher.encrypt(key_material)


class TestImportKeyMaterialWorkflow:

    def test_oaep_sha1_workflow(self, kms_client):
        """Full import workflow using RSAES_OAEP_SHA_1 wrapping algorithm."""
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id, "RSAES_OAEP_SHA_1")

        key_material = os.urandom(32)
        encrypted = _wrap_key_material(key_material, params['PublicKey'], "RSAES_OAEP_SHA_1")

        code, _ = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })
        assert code == 200

        code, desc = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        assert desc['KeyMetadata']['KeyState'] == 'Enabled'

    def test_oaep_sha256_workflow(self, kms_client):
        """Full import workflow: create EXTERNAL key, get params, import, encrypt/decrypt."""
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id, "RSAES_OAEP_SHA_256")

        key_material = os.urandom(32)
        encrypted = _wrap_key_material(key_material, params['PublicKey'], "RSAES_OAEP_SHA_256")

        code, import_resp = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })
        assert code == 200
        assert import_resp['KeyId'] is not None

        code, desc = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        assert desc['KeyMetadata']['KeyState'] == 'Enabled'
        assert desc['KeyMetadata']['Enabled'] is True

        pt = base64.b64encode(b"imported key test").decode()
        code, enc = kms_client.post('Encrypt', {"KeyId": key_id, "Plaintext": pt})
        assert code == 200

        code, dec = kms_client.post('Decrypt', {"CiphertextBlob": enc['CiphertextBlob']})
        assert code == 200
        assert dec['Plaintext'] == pt

    def test_pkcs1_v15_workflow(self, kms_client):
        """Import using RSAES_PKCS1_V1_5 wrapping algorithm."""
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id, "RSAES_PKCS1_V1_5")

        key_material = os.urandom(32)
        encrypted = _wrap_key_material(key_material, params['PublicKey'], "RSAES_PKCS1_V1_5")

        code, _ = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })
        assert code == 200

    def test_import_with_expiration(self, kms_client):
        """KEY_MATERIAL_EXPIRES sets ValidTo; DescribeKey returns it as a float."""
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)

        key_material = os.urandom(32)
        encrypted = _wrap_key_material(key_material, params['PublicKey'], "RSAES_OAEP_SHA_256")
        valid_to = int(time.time()) + 3600

        code, _ = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_EXPIRES",
            "ValidTo": valid_to,
        })
        assert code == 200

        code, desc = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        assert desc['KeyMetadata']['ExpirationModel'] == 'KEY_MATERIAL_EXPIRES'
        # ValidTo is set exactly from the int64 we sent; no rounding occurs
        assert desc['KeyMetadata']['ValidTo'] == valid_to

        pt = base64.b64encode(b"expiry key test").decode()
        code, enc = kms_client.post('Encrypt', {"KeyId": key_id, "Plaintext": pt})
        assert code == 200
        code, dec = kms_client.post('Decrypt', {"CiphertextBlob": enc['CiphertextBlob']})
        assert code == 200
        assert dec['Plaintext'] == pt

    def test_delete_and_reimport(self, kms_client):
        """Delete imported key material → state=PendingImport; re-import → Enabled again."""
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)

        key_material = os.urandom(32)
        encrypted = _wrap_key_material(key_material, params['PublicKey'], "RSAES_OAEP_SHA_256")
        kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })

        code, del_resp = kms_client.post('DeleteImportedKeyMaterial', {"KeyId": key_id})
        assert code == 200
        assert del_resp['KeyId'] is not None

        code, desc = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        assert desc['KeyMetadata']['KeyState'] == 'PendingImport'
        assert desc['KeyMetadata']['Enabled'] is False

        code, _ = kms_client.post('Encrypt', {
            "KeyId": key_id, "Plaintext": base64.b64encode(b"test").decode(),
        })
        assert code == 400

        # Re-import
        params2 = _get_import_params(kms_client, key_id)
        encrypted2 = _wrap_key_material(key_material, params2['PublicKey'], "RSAES_OAEP_SHA_256")
        code, _ = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params2['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted2).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })
        assert code == 200

        code, desc2 = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        assert desc2['KeyMetadata']['KeyState'] == 'Enabled'


class TestImportKeyMaterialErrors:

    def test_import_to_aws_kms_origin_key_fails(self, kms_client):
        """Importing into a key with Origin=AWS_KMS must fail."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        params = _get_import_params(kms_client, _create_external_key(kms_client))
        key_material = os.urandom(32)
        encrypted = _wrap_key_material(key_material, params['PublicKey'], "RSAES_OAEP_SHA_256")

        code, content = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })
        assert code == 400
        assert content['__type'] in ("UnsupportedOperationException", "KMSInvalidStateException")

    def test_import_with_wrong_token_fails(self, kms_client):
        """Using an import token from a different key must fail."""
        key_id1 = _create_external_key(kms_client)
        key_id2 = _create_external_key(kms_client)

        params1 = _get_import_params(kms_client, key_id1)
        params2 = _get_import_params(kms_client, key_id2)

        key_material = os.urandom(32)
        encrypted = _wrap_key_material(key_material, params2['PublicKey'], "RSAES_OAEP_SHA_256")

        # Use token from key1 but public key from key2
        code, content = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id1,
            "ImportToken": params1['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })
        assert code == 400

    def test_get_parameters_for_import_on_aws_kms_origin_fails(self, kms_client):
        """GetParametersForImport on a non-EXTERNAL key must fail."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, content = kms_client.post('GetParametersForImport', {
            "KeyId": key_id,
            "WrappingAlgorithm": "RSAES_OAEP_SHA_256",
            "WrappingKeySpec": "RSA_2048",
        })
        assert code == 400
        assert content['__type'] in ("UnsupportedOperationException", "InvalidStateException")

    def test_delete_imported_key_material_on_aws_kms_origin_fails(self, kms_client):
        """DeleteImportedKeyMaterial on an AWS_KMS origin key must fail."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, content = kms_client.post('DeleteImportedKeyMaterial', {"KeyId": key_id})
        assert code == 400
        assert content['__type'] in ("UnsupportedOperationException", "InvalidStateException")

    def test_omitted_expiration_model_with_valid_to_defaults_to_expires(self, kms_client):
        """Omitting ExpirationModel when ValidTo is set defaults to KEY_MATERIAL_EXPIRES."""
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")
        valid_to = int(time.time()) + 3600

        code, _ = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ValidTo": valid_to,
        })
        assert code == 200

        _, desc = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert desc['KeyMetadata']['ExpirationModel'] == 'KEY_MATERIAL_EXPIRES'

    def test_omitted_expiration_model_without_valid_to_defaults_to_no_expiry(self, kms_client):
        """Omitting both ExpirationModel and ValidTo defaults to KEY_MATERIAL_DOES_NOT_EXPIRE."""
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")

        code, _ = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
        })
        assert code == 200

        _, desc = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert desc['KeyMetadata']['ExpirationModel'] == 'KEY_MATERIAL_DOES_NOT_EXPIRE'

    def test_does_not_expire_with_valid_to_fails(self, kms_client):
        """KEY_MATERIAL_DOES_NOT_EXPIRE + ValidTo must return ValidationException."""
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")

        code, content = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
            "ValidTo": int(time.time()) + 3600,
        })
        assert code == 400
        assert content['__type'] == 'ValidationException'

    def test_response_key_id_is_arn(self, kms_client):
        """ImportKeyMaterial response KeyId must be the full ARN."""
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")

        code, resp = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })
        assert code == 200, resp
        assert resp['KeyId'].startswith("arn:"), f"KeyId not ARN: {resp['KeyId']}"

    def test_delete_imported_key_material_clears_valid_to_and_expiration_model(self, kms_client):
        """After DeleteImportedKeyMaterial, ValidTo and ExpirationModel must be absent from DescribeKey."""
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")
        valid_to = int(time.time()) + 3600

        kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_EXPIRES",
            "ValidTo": valid_to,
        })

        code, desc = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        assert desc['KeyMetadata']['ExpirationModel'] == 'KEY_MATERIAL_EXPIRES'
        assert 'ValidTo' in desc['KeyMetadata']

        code, _ = kms_client.post('DeleteImportedKeyMaterial', {"KeyId": key_id})
        assert code == 200

        code, desc2 = kms_client.post('DescribeKey', {"KeyId": key_id})
        assert code == 200
        assert desc2['KeyMetadata']['KeyState'] == 'PendingImport'
        assert 'ValidTo' not in desc2['KeyMetadata']
        assert 'ExpirationModel' not in desc2['KeyMetadata']


class TestImportKeyMaterialValidation:

    def test_missing_key_id_fails(self, kms_client):
        ext_key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, ext_key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")

        code, content = kms_client.post('ImportKeyMaterial', {
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })
        assert code == 400, content
        assert content['__type'] == 'MissingParameterException'

    def test_missing_import_token_fails(self, kms_client):
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")

        code, content = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })
        assert code == 400, content
        assert content['__type'] == 'MissingParameterException'

    def test_missing_encrypted_key_material_fails(self, kms_client):
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)

        code, content = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })
        assert code == 400, content
        assert content['__type'] == 'MissingParameterException'

    def test_key_material_expires_without_valid_to_fails(self, kms_client):
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")

        code, content = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_EXPIRES",
        })
        assert code == 400, content
        assert content['__type'] == 'ValidationException'

    def test_invalid_expiration_model_fails(self, kms_client):
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")

        code, content = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "INVALID_MODEL",
        })
        assert code == 400, content
        assert content['__type'] == 'ValidationException'

    def test_valid_to_in_past_fails(self, kms_client):
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")

        code, content = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_EXPIRES",
            "ValidTo": int(time.time()) - 3600,
        })
        assert code == 400, content
        assert content['__type'] == 'ValidationException'

    def test_nonexistent_key_fails(self, kms_client):
        ext_key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, ext_key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")

        code, content = kms_client.post('ImportKeyMaterial', {
            "KeyId": str(uuid4()),
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })
        assert code == 400, content
        assert content['__type'] == 'NotFoundException'

    def test_pending_deletion_key_fails(self, kms_client):
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")
        kms_client.post('ScheduleKeyDeletion', {"KeyId": key_id, "PendingWindowInDays": 7})

        code, content = kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })
        assert code == 400, content
        assert content['__type'] == 'KMSInvalidStateException'


class TestGetParametersForImportValidation:

    def test_missing_key_id_fails(self, kms_client):
        code, content = kms_client.post('GetParametersForImport', {
            "WrappingAlgorithm": "RSAES_OAEP_SHA_256",
            "WrappingKeySpec": "RSA_2048",
        })
        assert code == 400, content
        assert content['__type'] == 'MissingParameterException'

    def test_missing_wrapping_algorithm_fails(self, kms_client):
        key_id = _create_external_key(kms_client)
        code, content = kms_client.post('GetParametersForImport', {
            "KeyId": key_id,
            "WrappingKeySpec": "RSA_2048",
        })
        assert code == 400, content
        assert content['__type'] == 'MissingParameterException'

    def test_missing_wrapping_key_spec_fails(self, kms_client):
        key_id = _create_external_key(kms_client)
        code, content = kms_client.post('GetParametersForImport', {
            "KeyId": key_id,
            "WrappingAlgorithm": "RSAES_OAEP_SHA_256",
        })
        assert code == 400, content
        assert content['__type'] == 'MissingParameterException'

    def test_invalid_wrapping_algorithm_fails(self, kms_client):
        key_id = _create_external_key(kms_client)
        code, content = kms_client.post('GetParametersForImport', {
            "KeyId": key_id,
            "WrappingAlgorithm": "INVALID_ALGO",
            "WrappingKeySpec": "RSA_2048",
        })
        assert code == 400, content
        assert content['__type'] == 'ValidationException'

    def test_invalid_wrapping_key_spec_fails(self, kms_client):
        """local-kms only supports RSA_2048; other valid AWS specs return ValidationException."""
        key_id = _create_external_key(kms_client)
        code, content = kms_client.post('GetParametersForImport', {
            "KeyId": key_id,
            "WrappingAlgorithm": "RSAES_OAEP_SHA_256",
            "WrappingKeySpec": "RSA_4096",
        })
        assert code == 400, content
        assert content['__type'] == 'ValidationException'

    def test_nonexistent_key_fails(self, kms_client):
        code, content = kms_client.post('GetParametersForImport', {
            "KeyId": str(uuid4()),
            "WrappingAlgorithm": "RSAES_OAEP_SHA_256",
            "WrappingKeySpec": "RSA_2048",
        })
        assert code == 400, content
        assert content['__type'] == 'NotFoundException'

    def test_pending_deletion_key_fails(self, kms_client):
        key_id = _create_external_key(kms_client)
        kms_client.post('ScheduleKeyDeletion', {"KeyId": key_id, "PendingWindowInDays": 7})

        code, content = kms_client.post('GetParametersForImport', {
            "KeyId": key_id,
            "WrappingAlgorithm": "RSAES_OAEP_SHA_256",
            "WrappingKeySpec": "RSA_2048",
        })
        assert code == 400, content
        assert content['__type'] == 'KMSInvalidStateException'

    def test_response_shape(self, kms_client):
        """Response must include KeyId (ARN), ImportToken, PublicKey, ParametersValidTo."""
        key_id = _create_external_key(kms_client)
        code, resp = kms_client.post('GetParametersForImport', {
            "KeyId": key_id,
            "WrappingAlgorithm": "RSAES_OAEP_SHA_256",
            "WrappingKeySpec": "RSA_2048",
        })
        assert code == 200, resp
        assert resp['KeyId'].startswith("arn:"), f"KeyId not ARN: {resp['KeyId']}"
        assert 'ImportToken' in resp, resp
        assert 'PublicKey' in resp, resp
        assert 'ParametersValidTo' in resp, resp
        assert isinstance(resp['ParametersValidTo'], (int, float)), resp


class TestDeleteImportedKeyMaterialValidation:

    def test_missing_key_id_fails(self, kms_client):
        code, content = kms_client.post('DeleteImportedKeyMaterial', {})
        assert code == 400, content
        assert content['__type'] == 'MissingParameterException'

    def test_nonexistent_key_fails(self, kms_client):
        code, content = kms_client.post('DeleteImportedKeyMaterial', {"KeyId": str(uuid4())})
        assert code == 400, content
        assert content['__type'] == 'NotFoundException'

    def test_pending_deletion_key_fails(self, kms_client):
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")
        kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })
        kms_client.post('ScheduleKeyDeletion', {"KeyId": key_id, "PendingWindowInDays": 7})

        code, content = kms_client.post('DeleteImportedKeyMaterial', {"KeyId": key_id})
        assert code == 400, content
        assert content['__type'] == 'KMSInvalidStateException'

    def test_response_key_id_is_arn(self, kms_client):
        """DeleteImportedKeyMaterial response KeyId must be the full ARN."""
        key_id = _create_external_key(kms_client)
        params = _get_import_params(kms_client, key_id)
        encrypted = _wrap_key_material(os.urandom(32), params['PublicKey'], "RSAES_OAEP_SHA_256")
        kms_client.post('ImportKeyMaterial', {
            "KeyId": key_id,
            "ImportToken": params['ImportToken'],
            "EncryptedKeyMaterial": base64.b64encode(encrypted).decode(),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        })

        code, resp = kms_client.post('DeleteImportedKeyMaterial', {"KeyId": key_id})
        assert code == 200, resp
        assert resp['KeyId'].startswith("arn:"), f"KeyId not ARN: {resp['KeyId']}"

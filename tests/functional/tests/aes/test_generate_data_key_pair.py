"""
GenerateDataKeyPair and GenerateDataKeyPairWithoutPlaintext tests.
"""
import pytest
import base64
from uuid import uuid4
from oscrypto.asymmetric import load_private_key, dump_public_key


class TestGenerateDataKeyPair:

    @pytest.mark.parametrize("key_pair_spec", [
        'RSA_2048', 'RSA_3072', 'RSA_4096',
        'ECC_NIST_P256', 'ECC_NIST_P384', 'ECC_NIST_P521',
        'ECC_SECG_P256K1'
    ])
    def test_generate_key_pair(self, kms_client, symmetric_key, key_pair_spec):

        code, key_pair = kms_client.post('GenerateDataKeyPair', {
            'KeyId': symmetric_key['KeyId'],
            'KeyPairSpec': key_pair_spec,
            'EncryptionContext': {'test': 'true'},
        })

        assert code == 200
        assert isinstance(key_pair, dict)
        assert {'KeyId', 'KeyPairSpec', 'PrivateKeyCiphertextBlob', 'PrivateKeyPlaintext', 'PublicKey'}.issubset(set(key_pair.keys()))
        assert key_pair['KeyId'] == symmetric_key['Arn']
        assert key_pair['KeyPairSpec'] == key_pair_spec

        # Decrypt the private key blob and confirm it matches the plaintext
        code, decrypted = kms_client.post('Decrypt', {
            'KeyId': symmetric_key['KeyId'],
            'EncryptionContext': {'test': 'true'},
            'CiphertextBlob': key_pair['PrivateKeyCiphertextBlob']
        })

        assert code == 200
        assert decrypted['Plaintext'] == key_pair['PrivateKeyPlaintext']

        # Confirm the public key is derived from the private key
        private_key_plaintext = base64.b64decode(key_pair['PrivateKeyPlaintext'])
        private_key = load_private_key(private_key_plaintext)
        public_key = dump_public_key(private_key.public_key, encoding='der')

        public_key_encoded = str(base64.b64encode(public_key), "utf-8")
        assert public_key_encoded == key_pair['PublicKey']


    @pytest.mark.parametrize("key_pair_spec", [
        'RSA_2048', 'RSA_3072', 'RSA_4096',
        'ECC_NIST_P256', 'ECC_NIST_P384', 'ECC_NIST_P521',
        'ECC_SECG_P256K1'
    ])
    def test_generate_key_pair_without_plaintext(self, kms_client, symmetric_key, key_pair_spec):
        code, key_pair = kms_client.post('GenerateDataKeyPairWithoutPlaintext', {
            'KeyId': symmetric_key['KeyId'],
            'KeyPairSpec': key_pair_spec,
            'EncryptionContext': {'test': 'true'},
        })

        assert code == 200
        assert isinstance(key_pair, dict)
        assert {'KeyId', 'KeyPairSpec', 'PrivateKeyCiphertextBlob', 'PublicKey'}.issubset(set(key_pair.keys()))
        assert key_pair['KeyId'] == symmetric_key['Arn']
        assert key_pair['KeyPairSpec'] == key_pair_spec

        assert 'PrivateKeyPlaintext' not in key_pair.keys()


class TestGenerateDataKeyPairValidation:

    def test_missing_key_id_fails(self, kms_client):
        code, content = kms_client.post("GenerateDataKeyPair", {"KeyPairSpec": "RSA_2048"})
        assert code == 400
        assert content["__type"] == "MissingParameterException"

    def test_missing_key_pair_spec_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("GenerateDataKeyPair", {"KeyId": symmetric_key["KeyId"]})
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_invalid_key_pair_spec_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("GenerateDataKeyPair", {
            "KeyId": symmetric_key["KeyId"], "KeyPairSpec": "INVALID_SPEC",
        })
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_rsa_signing_key_as_encryptor_fails(self, kms_client, rsa_signing_key):
        """RSA SIGN_VERIFY key cannot encrypt the private key; must return InvalidKeyUsageException."""
        code, content = kms_client.post("GenerateDataKeyPair", {
            "KeyId": rsa_signing_key["KeyId"], "KeyPairSpec": "RSA_2048",
        })
        assert code == 400
        assert content["__type"] == "InvalidKeyUsageException"

    def test_disabled_key_fails(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("DisableKey", {"KeyId": key_id})

        code, content = kms_client.post("GenerateDataKeyPair", {
            "KeyId": key_id, "KeyPairSpec": "RSA_2048",
        })
        assert code == 400
        assert content["__type"] == "DisabledException"

    def test_pending_deletion_key_fails(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})

        code, content = kms_client.post("GenerateDataKeyPair", {
            "KeyId": key_id, "KeyPairSpec": "RSA_2048",
        })
        assert code == 400
        assert content["__type"] == "KMSInvalidStateException"

    def test_nonexistent_key_fails(self, kms_client):
        code, content = kms_client.post("GenerateDataKeyPair", {
            "KeyId": str(uuid4()), "KeyPairSpec": "RSA_2048",
        })
        assert code == 400
        assert content["__type"] == "NotFoundException"

    def test_via_alias_succeeds(self, kms_client, symmetric_key):
        """GenerateDataKeyPair resolves aliases; alias KeyId must succeed."""
        alias = f"alias/gdkp-{uuid4()}"
        kms_client.post("CreateAlias", {"TargetKeyId": symmetric_key["KeyId"], "AliasName": alias})

        code, resp = kms_client.post("GenerateDataKeyPair", {
            "KeyId": alias, "KeyPairSpec": "ECC_NIST_P256",
        })
        assert code == 200
        assert resp["KeyId"] == symmetric_key["Arn"]


class TestGenerateDataKeyPairWithoutPlaintextValidation:

    def test_missing_key_id_fails(self, kms_client):
        code, content = kms_client.post("GenerateDataKeyPairWithoutPlaintext", {"KeyPairSpec": "RSA_2048"})
        assert code == 400
        assert content["__type"] == "MissingParameterException"

    def test_missing_key_pair_spec_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("GenerateDataKeyPairWithoutPlaintext", {
            "KeyId": symmetric_key["KeyId"],
        })
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_invalid_key_pair_spec_fails(self, kms_client, symmetric_key):
        code, content = kms_client.post("GenerateDataKeyPairWithoutPlaintext", {
            "KeyId": symmetric_key["KeyId"], "KeyPairSpec": "INVALID_SPEC",
        })
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_disabled_key_fails(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("DisableKey", {"KeyId": key_id})

        code, content = kms_client.post("GenerateDataKeyPairWithoutPlaintext", {
            "KeyId": key_id, "KeyPairSpec": "ECC_NIST_P256",
        })
        assert code == 400
        assert content["__type"] == "DisabledException"

    def test_nonexistent_key_fails(self, kms_client):
        code, content = kms_client.post("GenerateDataKeyPairWithoutPlaintext", {
            "KeyId": str(uuid4()), "KeyPairSpec": "ECC_NIST_P256",
        })
        assert code == 400
        assert content["__type"] == "NotFoundException"

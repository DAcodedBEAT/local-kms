import hashlib
import pytest
from base64 import b64encode, b64decode


class TestSigning:

    @pytest.mark.parametrize("key_pair_spec_and_algorithm", [
        ('RSA_2048', 'RSASSA_PSS_SHA_256'),
        ('RSA_3072', 'RSASSA_PSS_SHA_384'),
        ('RSA_4096', 'RSASSA_PSS_SHA_512'),
        ('RSA_2048', 'RSASSA_PKCS1_V1_5_SHA_256'),
        ('RSA_3072', 'RSASSA_PKCS1_V1_5_SHA_384'),
        ('RSA_4096', 'RSASSA_PKCS1_V1_5_SHA_512'),
        ('ECC_NIST_P256', 'ECDSA_SHA_256'),
        ('ECC_NIST_P384', 'ECDSA_SHA_384'),
        ('ECC_NIST_P521', 'ECDSA_SHA_512'),
        ('ECC_SECG_P256K1', 'ECDSA_SHA_256'),
    ])
    def test_message_signing_roundtrip(self, kms_client, key_pair_spec_and_algorithm):
        key_spec, algorithm = key_pair_spec_and_algorithm
        code, cmk = kms_client.post('CreateKey', {
            "CustomerMasterKeySpec": key_spec,
            "KeyUsage": "SIGN_VERIFY",
        })
        assert code == 200
        key_id = cmk['KeyMetadata']['KeyId']

        message = b64encode(b'Hello World').decode('ascii')

        code, signed = kms_client.post('Sign', {
            'KeyId': key_id,
            'MessageType': 'RAW',
            'SigningAlgorithm': algorithm,
            'Message': message,
        })
        assert code == 200
        assert 'Signature' in signed
        assert signed['KeyId'] == cmk['KeyMetadata']['Arn']
        assert signed['SigningAlgorithm'] == algorithm

        code, verified = kms_client.post('Verify', {
            'KeyId': key_id,
            'MessageType': 'RAW',
            'SigningAlgorithm': algorithm,
            'Message': message,
            'Signature': signed['Signature'],
        })
        assert code == 200
        assert verified['SignatureValid'] is True
        assert verified['KeyId'] == cmk['KeyMetadata']['Arn']
        assert verified['SigningAlgorithm'] == algorithm

        kms_client.post('ScheduleKeyDeletion', {'KeyId': key_id, 'PendingWindowInDays': 7})

    def test_digest_signing_rsa(self, kms_client, rsa_signing_key):
        digest = hashlib.sha256(b'Hello World').digest()

        code, signed = kms_client.post('Sign', {
            'KeyId': rsa_signing_key['KeyId'],
            'MessageType': 'DIGEST',
            'SigningAlgorithm': 'RSASSA_PSS_SHA_256',
            'Message': b64encode(digest).decode('ascii'),
        })
        assert code == 200
        assert 'Signature' in signed

        code, verified = kms_client.post('Verify', {
            'KeyId': rsa_signing_key['KeyId'],
            'MessageType': 'DIGEST',
            'SigningAlgorithm': 'RSASSA_PSS_SHA_256',
            'Message': b64encode(digest).decode('ascii'),
            'Signature': signed['Signature'],
        })
        assert code == 200
        assert verified['SignatureValid'] is True

    def test_digest_signing_ecc(self, kms_client, ecc_signing_key):
        """DIGEST message type must work for ECC keys too."""
        digest = hashlib.sha256(b'Hello World').digest()

        code, signed = kms_client.post('Sign', {
            'KeyId': ecc_signing_key['KeyId'],
            'MessageType': 'DIGEST',
            'SigningAlgorithm': 'ECDSA_SHA_256',
            'Message': b64encode(digest).decode('ascii'),
        })
        assert code == 200

        code, verified = kms_client.post('Verify', {
            'KeyId': ecc_signing_key['KeyId'],
            'MessageType': 'DIGEST',
            'SigningAlgorithm': 'ECDSA_SHA_256',
            'Message': b64encode(digest).decode('ascii'),
            'Signature': signed['Signature'],
        })
        assert code == 200
        assert verified['SignatureValid'] is True


class TestVerifyFailures:
    """
    AWS Verify never returns SignatureValid=false.
    An invalid signature raises KMSInvalidSignatureException (HTTP 400).
    """

    def test_tampered_signature_fails(self, kms_client, rsa_signing_key):
        """Bit-flipped signature must raise KMSInvalidSignatureException, not return false."""
        message = b64encode(b'tamper test').decode()

        _, signed = kms_client.post('Sign', {
            'KeyId': rsa_signing_key['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': 'RSASSA_PSS_SHA_256',
            'Message': message,
        })
        tampered = bytearray(b64decode(signed['Signature']))
        tampered[-1] ^= 0xFF

        code, content = kms_client.post('Verify', {
            'KeyId': rsa_signing_key['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': 'RSASSA_PSS_SHA_256',
            'Message': message,
            'Signature': b64encode(bytes(tampered)).decode(),
        })
        assert code == 400
        assert content['__type'] == 'KMSInvalidSignatureException'

    def test_tampered_message_fails(self, kms_client, rsa_signing_key):
        """Modified message on Verify must raise KMSInvalidSignatureException."""
        message = b64encode(b'original message').decode()
        tampered = b64encode(b'tampered message').decode()

        _, signed = kms_client.post('Sign', {
            'KeyId': rsa_signing_key['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': 'RSASSA_PKCS1_V1_5_SHA_256',
            'Message': message,
        })

        code, content = kms_client.post('Verify', {
            'KeyId': rsa_signing_key['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': 'RSASSA_PKCS1_V1_5_SHA_256',
            'Message': tampered,
            'Signature': signed['Signature'],
        })
        assert code == 400
        assert content['__type'] == 'KMSInvalidSignatureException'

    def test_wrong_algorithm_on_verify_fails(self, kms_client, rsa_signing_key):
        """
        Verifying with a different algorithm than was used to sign must fail.
        local-kms returns InvalidKeyUsageException when the crypto operation errors
        (verify.go:117), distinct from KMSInvalidSignatureException (bad signature, same algo).
        """
        message = b64encode(b'algorithm mismatch').decode()

        _, signed = kms_client.post('Sign', {
            'KeyId': rsa_signing_key['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': 'RSASSA_PSS_SHA_256',
            'Message': message,
        })

        code, content = kms_client.post('Verify', {
            'KeyId': rsa_signing_key['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': 'RSASSA_PKCS1_V1_5_SHA_256',
            'Message': message,
            'Signature': signed['Signature'],
        })
        assert code == 400
        # local-kms routes verify errors through InvalidKeyUsageException
        assert content['__type'] in ('InvalidKeyUsageException', 'KMSInvalidSignatureException')

    def test_ecc_tampered_signature_fails(self, kms_client, ecc_signing_key):
        message = b64encode(b'ecc tamper test').decode()

        _, signed = kms_client.post('Sign', {
            'KeyId': ecc_signing_key['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': 'ECDSA_SHA_256',
            'Message': message,
        })
        tampered = bytearray(b64decode(signed['Signature']))
        tampered[-1] ^= 0xFF

        code, content = kms_client.post('Verify', {
            'KeyId': ecc_signing_key['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': 'ECDSA_SHA_256',
            'Message': message,
            'Signature': b64encode(bytes(tampered)).decode(),
        })
        assert code == 400
        assert content['__type'] == 'KMSInvalidSignatureException'

    def test_sign_with_disabled_key_fails(self, kms_client):
        _, resp = kms_client.post('CreateKey', {
            'KeySpec': 'RSA_2048', 'KeyUsage': 'SIGN_VERIFY',
        })
        key_id = resp['KeyMetadata']['KeyId']
        kms_client.post('DisableKey', {'KeyId': key_id})

        code, content = kms_client.post('Sign', {
            'KeyId': key_id,
            'MessageType': 'RAW',
            'SigningAlgorithm': 'RSASSA_PSS_SHA_256',
            'Message': b64encode(b'test').decode(),
        })
        assert code == 400
        assert content['__type'] == 'DisabledException'

    def test_sign_with_symmetric_key_fails(self, kms_client, symmetric_key):
        """Symmetric key cannot be used for signing."""
        code, content = kms_client.post('Sign', {
            'KeyId': symmetric_key['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': 'RSASSA_PSS_SHA_256',
            'Message': b64encode(b'test').decode(),
        })
        assert code == 400
        assert content['__type'] == 'InvalidKeyUsageException'

    def test_sign_empty_message_fails(self, kms_client, rsa_signing_key):
        """Sign with empty message must return ValidationException (min length 1)."""
        code, content = kms_client.post('Sign', {
            'KeyId': rsa_signing_key['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': 'RSASSA_PSS_SHA_256',
            'Message': b64encode(b'').decode(),
        })
        assert code == 400
        assert content['__type'] == 'ValidationException'

    def test_verify_empty_message_fails(self, kms_client, rsa_signing_key):
        """Verify with empty message must return ValidationException (min length 1)."""
        dummy_sig = b64encode(b'x' * 256).decode()
        code, content = kms_client.post('Verify', {
            'KeyId': rsa_signing_key['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': 'RSASSA_PSS_SHA_256',
            'Message': b64encode(b'').decode(),
            'Signature': dummy_sig,
        })
        assert code == 400
        assert content['__type'] == 'ValidationException'

    def test_sign_with_rsa_encrypt_decrypt_key_fails(self, kms_client, rsa_encryption_key):
        """RSA ENCRYPT_DECRYPT key cannot be used for signing; must return InvalidKeyUsageException."""
        code, content = kms_client.post('Sign', {
            'KeyId': rsa_encryption_key['KeyId'],
            'MessageType': 'RAW',
            'SigningAlgorithm': 'RSASSA_PSS_SHA_256',
            'Message': b64encode(b'test message').decode(),
        })
        assert code == 400
        assert content['__type'] == 'InvalidKeyUsageException'

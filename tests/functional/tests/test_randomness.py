import base64
import pytest


class TestGenerateRandom:

    @pytest.mark.parametrize("n", [1, 16, 32, 256, 1024])
    def test_generate_random_correct_length(self, kms_client, n):
        code, resp = kms_client.post("GenerateRandom", {"NumberOfBytes": n})
        assert code == 200
        assert "Plaintext" in resp
        assert len(base64.b64decode(resp["Plaintext"])) == n

    def test_generate_random_boundary_max_1024(self, kms_client):
        code, resp = kms_client.post("GenerateRandom", {"NumberOfBytes": 1024})
        assert code == 200
        assert len(base64.b64decode(resp["Plaintext"])) == 1024

    def test_generate_random_boundary_min_1(self, kms_client):
        code, resp = kms_client.post("GenerateRandom", {"NumberOfBytes": 1})
        assert code == 200
        assert len(base64.b64decode(resp["Plaintext"])) == 1

    def test_two_calls_produce_different_output(self, kms_client):
        """Output must be random — two successive calls should not be identical."""
        _, resp1 = kms_client.post("GenerateRandom", {"NumberOfBytes": 32})
        _, resp2 = kms_client.post("GenerateRandom", {"NumberOfBytes": 32})
        assert resp1["Plaintext"] != resp2["Plaintext"]

    def test_missing_number_of_bytes_fails(self, kms_client):
        """NumberOfBytes is required; omitting it must fail with ValidationException."""
        code, resp = kms_client.post("GenerateRandom", {})
        assert code == 400
        assert resp["__type"] == "ValidationException"

    @pytest.mark.parametrize("n", [0, 1025])
    def test_out_of_range_fails(self, kms_client, n):
        """Valid range is 1–1024 inclusive; values outside must fail."""
        code, resp = kms_client.post("GenerateRandom", {"NumberOfBytes": n})
        assert code == 400
        assert resp["__type"] == "ValidationException"

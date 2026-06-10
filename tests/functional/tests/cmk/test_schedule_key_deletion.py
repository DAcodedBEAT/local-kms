"""
ScheduleKeyDeletion and CancelKeyDeletion tests.

Verifies AWS-compatible response shape, field types, validation, and state transitions.
"""
import base64
import time
from uuid import uuid4

import pytest


class TestScheduleKeyDeletionResponse:

    def test_response_contains_all_required_fields(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        key_arn = resp["KeyMetadata"]["Arn"]

        code, delete = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": key_id, "PendingWindowInDays": 7,
        })
        assert code == 200
        assert {"KeyId", "DeletionDate", "KeyState", "PendingWindowInDays"}.issubset(delete.keys())

    def test_key_id_in_response_is_arn(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        key_arn = resp["KeyMetadata"]["Arn"]

        _, delete = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": key_id, "PendingWindowInDays": 7,
        })
        assert delete["KeyId"] == key_arn

    def test_deletion_date_is_float(self, kms_client):
        """DeletionDate must be a float (Unix epoch) per AWS Timestamp type."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]

        _, delete = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": key_id, "PendingWindowInDays": 7,
        })
        assert isinstance(delete["DeletionDate"], float)

    def test_deletion_date_is_approximately_now_plus_window(self, kms_client):
        """DeletionDate should be ~7 days from now when PendingWindowInDays=7."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        before = time.time()

        _, delete = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": key_id, "PendingWindowInDays": 7,
        })
        after = time.time()

        expected_seconds = 7 * 86400
        assert before + expected_seconds <= delete["DeletionDate"] <= after + expected_seconds + 5

    def test_key_state_is_pending_deletion(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]

        _, delete = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": key_id, "PendingWindowInDays": 7,
        })
        assert delete["KeyState"] == "PendingDeletion"

    def test_pending_window_in_days_reflects_requested_value(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]

        _, delete = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": key_id, "PendingWindowInDays": 14,
        })
        assert delete["PendingWindowInDays"] == 14

    def test_default_pending_window_is_30_days(self, kms_client):
        """Omitting PendingWindowInDays defaults to 30."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]

        _, delete = kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id})
        assert delete["PendingWindowInDays"] == 30

    def test_can_schedule_via_key_arn(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_arn = resp["KeyMetadata"]["Arn"]

        code, delete = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": key_arn, "PendingWindowInDays": 7,
        })
        assert code == 200
        assert delete["KeyId"] == key_arn


class TestScheduleKeyDeletionValidation:

    def test_missing_key_id_fails(self, kms_client):
        """KeyId is required; omitting it must return MissingParameterException."""
        code, content = kms_client.post("ScheduleKeyDeletion", {"PendingWindowInDays": 7})
        assert code == 400
        assert content["__type"] == "MissingParameterException"

    def test_pending_window_boundary_7_succeeds(self, kms_client):
        """PendingWindowInDays=7 is the minimum valid value."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        code, delete = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": key_id, "PendingWindowInDays": 7,
        })
        assert code == 200
        assert delete["PendingWindowInDays"] == 7

    def test_pending_window_boundary_30_succeeds(self, kms_client):
        """PendingWindowInDays=30 is the maximum valid value."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        code, delete = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": key_id, "PendingWindowInDays": 30,
        })
        assert code == 200
        assert delete["PendingWindowInDays"] == 30

    def test_schedule_disabled_key_succeeds(self, kms_client):
        """Disabled key is a valid state for ScheduleKeyDeletion; must succeed."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        kms_client.post("DisableKey", {"KeyId": key_id})

        code, delete = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": key_id, "PendingWindowInDays": 7,
        })
        assert code == 200
        assert delete["KeyState"] == "PendingDeletion"

    def test_schedule_via_alias_fails(self, kms_client):
        """ScheduleKeyDeletion accepts only key ID or ARN; alias must return NotFoundException."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        alias = f"alias/sched-{uuid4()}"
        kms_client.post("CreateAlias", {"TargetKeyId": key_id, "AliasName": alias})

        code, content = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": alias, "PendingWindowInDays": 7,
        })
        assert code == 400
        assert content["__type"] == "NotFoundException"

    def test_pending_window_below_7_fails(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]

        code, content = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": key_id, "PendingWindowInDays": 6,
        })
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_pending_window_above_30_fails(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]

        code, content = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": key_id, "PendingWindowInDays": 31,
        })
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_nonexistent_key_fails(self, kms_client):
        code, content = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": str(uuid4()), "PendingWindowInDays": 7,
        })
        assert code == 400
        assert content["__type"] == "NotFoundException"

    def test_already_pending_deletion_fails(self, kms_client):
        """Re-scheduling a key already pending deletion is rejected."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]

        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})

        code, content = kms_client.post("ScheduleKeyDeletion", {
            "KeyId": key_id, "PendingWindowInDays": 7,
        })
        assert code == 400
        assert content["__type"] == "KMSInvalidStateException"


class TestCancelKeyDeletion:

    def test_cancel_returns_key_to_disabled(self, kms_client):
        """After cancel, key state must be Disabled (not Enabled — AWS behaviour)."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]

        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})

        code, cancel = kms_client.post("CancelKeyDeletion", {"KeyId": key_id})
        assert code == 200
        assert cancel["KeyId"] == resp["KeyMetadata"]["Arn"]

        _, described = kms_client.post("DescribeKey", {"KeyId": key_id})
        assert described["KeyMetadata"]["KeyState"] == "Disabled"

    def test_cancel_clears_deletion_date(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]

        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})
        kms_client.post("CancelKeyDeletion", {"KeyId": key_id})

        _, described = kms_client.post("DescribeKey", {"KeyId": key_id})
        assert "DeletionDate" not in described["KeyMetadata"] or described["KeyMetadata"]["DeletionDate"] == 0

    def test_can_reenable_after_cancel(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]

        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})
        kms_client.post("CancelKeyDeletion", {"KeyId": key_id})
        kms_client.post("EnableKey", {"KeyId": key_id})

        _, described = kms_client.post("DescribeKey", {"KeyId": key_id})
        assert described["KeyMetadata"]["KeyState"] == "Enabled"

    def test_cancel_missing_key_id_fails(self, kms_client):
        """KeyId is required; omitting it must return MissingParameterException."""
        code, content = kms_client.post("CancelKeyDeletion", {})
        assert code == 400
        assert content["__type"] == "MissingParameterException"

    def test_cancel_nonexistent_key_fails(self, kms_client):
        """CancelKeyDeletion on a nonexistent key must return NotFoundException."""
        code, content = kms_client.post("CancelKeyDeletion", {"KeyId": str(uuid4())})
        assert code == 400
        assert content["__type"] == "NotFoundException"

    def test_cancel_via_alias_fails(self, kms_client):
        """CancelKeyDeletion accepts only key ID or ARN; alias must return NotFoundException."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        alias = f"alias/cancel-{uuid4()}"
        kms_client.post("CreateAlias", {"TargetKeyId": key_id, "AliasName": alias})
        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})

        code, content = kms_client.post("CancelKeyDeletion", {"KeyId": alias})
        assert code == 400
        assert content["__type"] == "NotFoundException"

    def test_cancel_non_pending_key_fails(self, kms_client):
        """CancelKeyDeletion on a key not in PendingDeletion must return KMSInvalidStateException."""
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]

        code, content = kms_client.post("CancelKeyDeletion", {"KeyId": key_id})
        assert code == 400
        assert content["__type"] == "KMSInvalidStateException"

    def test_encrypt_works_after_cancel_and_reenable(self, kms_client):
        _, resp = kms_client.post("CreateKey", {})
        key_id = resp["KeyMetadata"]["KeyId"]
        pt = base64.b64encode(b"cancel and re-enable test").decode()

        kms_client.post("ScheduleKeyDeletion", {"KeyId": key_id, "PendingWindowInDays": 7})
        kms_client.post("CancelKeyDeletion", {"KeyId": key_id})
        kms_client.post("EnableKey", {"KeyId": key_id})

        code, enc = kms_client.post("Encrypt", {"KeyId": key_id, "Plaintext": pt})
        assert code == 200

        code, dec = kms_client.post("Decrypt", {"CiphertextBlob": enc["CiphertextBlob"]})
        assert code == 200
        assert dec["Plaintext"] == pt

"""
Pagination tests for ListAliases, ListKeys, and ListResourceTags.

Uses Limit=1 to force pagination without creating large numbers of resources.
"""
import base64
from uuid import uuid4


class TestListAliasesPagination:

    def test_truncated_when_results_exceed_limit(self, kms_client):
        """When results exceed Limit, Truncated=true and NextMarker is set."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        alias1 = f"alias/{uuid4()}"
        alias2 = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": key_id, "AliasName": alias1})
        kms_client.post('CreateAlias', {"TargetKeyId": key_id, "AliasName": alias2})

        code, page1 = kms_client.post('ListAliases', {"KeyId": key_id, "Limit": 1})
        assert code == 200
        assert page1['Truncated'] is True
        assert 'NextMarker' in page1
        assert len(page1['Aliases']) == 1

    def test_next_page_via_marker(self, kms_client):
        """NextMarker from page 1 returns the remaining items on page 2."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        alias1 = f"alias/{uuid4()}"
        alias2 = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": key_id, "AliasName": alias1})
        kms_client.post('CreateAlias', {"TargetKeyId": key_id, "AliasName": alias2})

        _, page1 = kms_client.post('ListAliases', {"KeyId": key_id, "Limit": 1})
        marker = page1['NextMarker']

        code, page2 = kms_client.post('ListAliases', {
            "KeyId": key_id, "Limit": 1, "Marker": marker,
        })
        assert code == 200
        assert len(page2['Aliases']) >= 1

        # Combined pages cover both aliases
        all_names = {a['AliasName'] for a in page1['Aliases']} | {a['AliasName'] for a in page2['Aliases']}
        assert alias1 in all_names
        assert alias2 in all_names

    def test_last_page_not_truncated(self, kms_client):
        """Final page has Truncated=false."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        alias1 = f"alias/{uuid4()}"
        alias2 = f"alias/{uuid4()}"
        kms_client.post('CreateAlias', {"TargetKeyId": key_id, "AliasName": alias1})
        kms_client.post('CreateAlias', {"TargetKeyId": key_id, "AliasName": alias2})

        _, page1 = kms_client.post('ListAliases', {"KeyId": key_id, "Limit": 1})
        marker = page1['NextMarker']

        code, page2 = kms_client.post('ListAliases', {
            "KeyId": key_id, "Limit": 100, "Marker": marker,
        })
        assert code == 200
        assert page2['Truncated'] is False
        assert 'NextMarker' not in page2

    def test_invalid_marker_fails(self, kms_client, symmetric_key):
        """An invalid/garbage marker must return InvalidMarkerException."""
        code, content = kms_client.post('ListAliases', {
            "KeyId": symmetric_key['KeyId'], "Marker": "invalid-marker-value",
        })
        assert code == 400
        assert content["__type"] == "InvalidMarkerException"

    def test_limit_below_1_fails(self, kms_client):
        code, content = kms_client.post('ListAliases', {"Limit": 0})
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_limit_above_100_fails(self, kms_client):
        code, content = kms_client.post('ListAliases', {"Limit": 101})
        assert code == 400
        assert content["__type"] == "ValidationException"


class TestListKeys:

    def test_response_shape(self, kms_client):
        """Response must include Keys list and Truncated boolean."""
        code, resp = kms_client.post('ListKeys', {})
        assert code == 200
        assert 'Keys' in resp
        assert 'Truncated' in resp
        assert isinstance(resp['Truncated'], bool)

    def test_entry_has_key_arn_and_key_id(self, kms_client):
        """Each entry must have both KeyArn and KeyId fields."""
        _, r = kms_client.post('CreateKey', {})
        created_id = r['KeyMetadata']['KeyId']
        created_arn = r['KeyMetadata']['Arn']

        _, resp = kms_client.post('ListKeys', {"Limit": 1000})
        entry = next((k for k in resp['Keys'] if k['KeyId'] == created_id), None)
        assert entry is not None, "Created key not found in ListKeys"
        assert entry['KeyArn'] == created_arn

    def test_invalid_marker_fails(self, kms_client):
        """Invalid marker must return InvalidMarkerException."""
        code, content = kms_client.post('ListKeys', {"Marker": "invalid-marker-xyz"})
        assert code == 400
        assert content["__type"] == "InvalidMarkerException"

    def test_limit_boundary_1_succeeds(self, kms_client):
        code, resp = kms_client.post('ListKeys', {"Limit": 1})
        assert code == 200

    def test_limit_boundary_1000_succeeds(self, kms_client):
        code, resp = kms_client.post('ListKeys', {"Limit": 1000})
        assert code == 200


class TestListKeysPagination:

    def test_truncated_when_results_exceed_limit(self, kms_client):
        """ListKeys with Limit=1 returns Truncated=true when more keys exist."""
        kms_client.post('CreateKey', {})
        kms_client.post('CreateKey', {})

        code, page1 = kms_client.post('ListKeys', {"Limit": 1})
        assert code == 200
        assert page1['Truncated'] is True
        assert 'NextMarker' in page1
        assert len(page1['Keys']) == 1

    def test_next_page_via_marker(self, kms_client):
        """All keys are reachable by following NextMarker."""
        _, r1 = kms_client.post('CreateKey', {})
        _, r2 = kms_client.post('CreateKey', {})
        key1_id = r1['KeyMetadata']['KeyId']
        key2_id = r2['KeyMetadata']['KeyId']

        all_ids = set()
        marker = None
        for _ in range(1000):
            params = {"Limit": 1}
            if marker:
                params["Marker"] = marker
            _, page = kms_client.post('ListKeys', params)
            all_ids.update(k['KeyId'] for k in page['Keys'])
            if not page['Truncated']:
                break
            marker = page['NextMarker']

        assert key1_id in all_ids
        assert key2_id in all_ids

    def test_last_page_not_truncated(self, kms_client):
        """Final page must have Truncated=false and no NextMarker."""
        _, r1 = kms_client.post('CreateKey', {})
        _, r2 = kms_client.post('CreateKey', {})

        _, page1 = kms_client.post('ListKeys', {"Limit": 1})
        marker = page1['NextMarker']

        _, page2 = kms_client.post('ListKeys', {"Limit": 1000, "Marker": marker})
        assert page2['Truncated'] is False
        assert 'NextMarker' not in page2

    def test_limit_below_1_fails(self, kms_client):
        code, content = kms_client.post('ListKeys', {"Limit": 0})
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_limit_above_1000_fails(self, kms_client):
        code, content = kms_client.post('ListKeys', {"Limit": 1001})
        assert code == 400
        assert content["__type"] == "ValidationException"


class TestListResourceTagsPagination:

    def test_truncated_when_tags_exceed_limit(self, kms_client):
        """ListResourceTags with Limit=1 truncates when key has multiple tags."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        kms_client.post('TagResource', {"KeyId": key_id, "Tags": [
            {"TagKey": "tag-a", "TagValue": "val-a"},
            {"TagKey": "tag-b", "TagValue": "val-b"},
        ]})

        code, page1 = kms_client.post('ListResourceTags', {"KeyId": key_id, "Limit": 1})
        assert code == 200
        assert page1['Truncated'] is True
        assert 'NextMarker' in page1
        assert len(page1['Tags']) == 1

    def test_next_page_via_marker_covers_all_tags(self, kms_client):
        """All tags reachable via pagination."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        kms_client.post('TagResource', {"KeyId": key_id, "Tags": [
            {"TagKey": "p-tag-a", "TagValue": "val-a"},
            {"TagKey": "p-tag-b", "TagValue": "val-b"},
        ]})

        _, page1 = kms_client.post('ListResourceTags', {"KeyId": key_id, "Limit": 1})
        marker = page1['NextMarker']

        code, page2 = kms_client.post('ListResourceTags', {
            "KeyId": key_id, "Limit": 1, "Marker": marker,
        })
        assert code == 200
        all_keys = {t['TagKey'] for t in page1['Tags']} | {t['TagKey'] for t in page2['Tags']}
        assert "p-tag-a" in all_keys
        assert "p-tag-b" in all_keys

    def test_limit_below_1_fails(self, kms_client):
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        code, content = kms_client.post('ListResourceTags', {"KeyId": key_id, "Limit": 0})
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_limit_above_1000_fails(self, kms_client):
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        code, content = kms_client.post('ListResourceTags', {"KeyId": key_id, "Limit": 1001})
        assert code == 400
        assert content["__type"] == "ValidationException"

    def test_limit_1000_succeeds(self, kms_client):
        """Limit=1000 is the maximum allowed value."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']
        code, _ = kms_client.post('ListResourceTags', {"KeyId": key_id, "Limit": 1000})
        assert code == 200

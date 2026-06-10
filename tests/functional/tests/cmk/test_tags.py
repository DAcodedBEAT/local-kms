"""
Tests for TagResource, UntagResource, and ListResourceTags.
"""
from uuid import uuid4


class TestTagResourceCRUD:

    def test_create_key_with_tags_succeeds(self, kms_client):
        """Tags specified at CreateKey time must appear in ListResourceTags."""
        code, content = kms_client.post('CreateKey', {
            "Tags": [
                {"TagKey": "Environment", "TagValue": "Test"},
                {"TagKey": "Application", "TagValue": "LocalKMS"},
            ]
        })
        assert code == 200
        key_id = content['KeyMetadata']['KeyId']

        code, tags_resp = kms_client.post('ListResourceTags', {"KeyId": key_id})
        assert code == 200
        tag_keys = [t['TagKey'] for t in tags_resp['Tags']]
        assert 'Environment' in tag_keys
        assert 'Application' in tag_keys

    def test_tag_resource_adds_tag(self, kms_client):
        """TagResource on an existing key; tag must appear in ListResourceTags."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, _ = kms_client.post('TagResource', {
            "KeyId": key_id,
            "Tags": [{"TagKey": "Owner", "TagValue": "TeamA"}],
        })
        assert code == 200

        code, tags_resp = kms_client.post('ListResourceTags', {"KeyId": key_id})
        assert code == 200
        owner_tags = [t for t in tags_resp['Tags'] if t['TagKey'] == 'Owner']
        assert len(owner_tags) == 1
        assert owner_tags[0]['TagValue'] == 'TeamA'

    def test_untag_resource_removes_tag(self, kms_client):
        """UntagResource must remove the tag; it must not appear in subsequent ListResourceTags."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        kms_client.post('TagResource', {
            "KeyId": key_id,
            "Tags": [{"TagKey": "ToDelete", "TagValue": "DeleteMe"}],
        })

        code, _ = kms_client.post('UntagResource', {"KeyId": key_id, "TagKeys": ["ToDelete"]})
        assert code == 200

        code, tags_resp = kms_client.post('ListResourceTags', {"KeyId": key_id})
        assert code == 200
        deleted = [t for t in tags_resp['Tags'] if t['TagKey'] == 'ToDelete']
        assert len(deleted) == 0


class TestTagResourceNotFound:

    def test_tag_nonexistent_key_fails(self, kms_client):
        """TagResource on an unknown key must return NotFoundException."""
        code, content = kms_client.post('TagResource', {
            "KeyId": str(uuid4()),
            "Tags": [{"TagKey": "k", "TagValue": "v"}],
        })
        assert code == 400
        assert content['__type'] == 'NotFoundException'

    def test_untag_nonexistent_key_fails(self, kms_client):
        """UntagResource on an unknown key must return NotFoundException."""
        code, content = kms_client.post('UntagResource', {
            "KeyId": str(uuid4()),
            "TagKeys": ["k"],
        })
        assert code == 400
        assert content['__type'] == 'NotFoundException'

    def test_list_tags_nonexistent_key_fails(self, kms_client):
        """ListResourceTags on an unknown key must return NotFoundException."""
        code, content = kms_client.post('ListResourceTags', {"KeyId": str(uuid4())})
        assert code == 400
        assert content['__type'] == 'NotFoundException'


class TestTagResourceValidation:

    def test_aws_prefix_tag_rejected(self, kms_client):
        """TagResource must reject tags whose key starts with 'aws:' (reserved prefix)."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        code, content = kms_client.post('TagResource', {
            "KeyId": key_id,
            "Tags": [{"TagKey": "aws:reserved", "TagValue": "value"}],
        })
        assert code == 400
        assert content['__type'] == 'TagException'

    def test_tag_quota_enforced(self, kms_client):
        """TagResource must fail with TagException when adding tags would exceed the 50-tag limit."""
        _, resp = kms_client.post('CreateKey', {})
        key_id = resp['KeyMetadata']['KeyId']

        # Add 50 tags (the maximum allowed)
        tags = [{"TagKey": f"tag-{i}", "TagValue": "v"} for i in range(50)]
        code, _ = kms_client.post('TagResource', {"KeyId": key_id, "Tags": tags})
        assert code == 200

        # Adding one more tag must fail
        code, content = kms_client.post('TagResource', {
            "KeyId": key_id,
            "Tags": [{"TagKey": "tag-overflow", "TagValue": "v"}],
        })
        assert code == 400
        assert content['__type'] == 'TagException'

import re


def assert_error_response(response, error_type, error_message_expression=None):
    assert isinstance(response, dict), (
        f"Expected dict response, got {type(response).__name__}: {response!r}"
    )
    assert '__type' in response, f"Missing '__type' in error response: {response}"
    assert 'message' in response, f"Missing 'message' in error response: {response}"
    assert response['__type'] == error_type, (
        f"Expected error type '{error_type}', got '{response['__type']}'"
    )
    if error_message_expression is not None:
        pattern = re.compile(error_message_expression)
        assert pattern.match(response['message']), (
            f"Message '{response['message']}' did not match pattern '{error_message_expression}'"
        )

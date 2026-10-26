"""Ambiguous configuration must fail before policy or custody is touched."""

import pytest

from pap.configuration import ConfigurationError, parse_config_json


def test_valid_configuration_preserves_types_and_values():
    assert parse_config_json(b'{"enabled":false,"nested":{"count":2,"ttl":1.5},"items":[null,true]}') == {
        "enabled": False,
        "nested": {"count": 2, "ttl": 1.5},
        "items": [None, True],
    }


@pytest.mark.parametrize("raw", [b'{"grant":1,"grant":2}', b'{"outer":{"grant":1,"grant":2}}'])
def test_duplicate_members_fail_at_every_object_level(raw):
    with pytest.raises(ConfigurationError, match="^configuration_duplicate_member$"):
        parse_config_json(raw)


@pytest.mark.parametrize("number", [b"NaN", b"Infinity", b"-Infinity", b"1e400", b"-1e400"])
def test_nonfinite_numbers_are_not_policy_expiries(number):
    with pytest.raises(ConfigurationError, match="^configuration_nonfinite_number$"):
        parse_config_json(b'{"grant_expires_at":' + number + b"}")


@pytest.mark.parametrize("raw", [b"", b"{", b'{"credential":"synthetic-sensitive-value",}', b"\xff"])
def test_errors_do_not_repeat_configuration_content(raw):
    with pytest.raises(ConfigurationError) as error:
        parse_config_json(raw)
    assert str(error.value) == "configuration_json_invalid"
    assert "synthetic-sensitive-value" not in str(error.value)


@pytest.mark.parametrize("raw", [b"null", b"true", b"[]", b'"object required"'])
def test_nonobject_roots_are_rejected(raw):
    with pytest.raises(ConfigurationError, match="^configuration_object_required$"):
        parse_config_json(raw)


def test_size_and_depth_are_bounded():
    with pytest.raises(ConfigurationError, match="^configuration_too_large$"):
        parse_config_json(b'{"a":1}', maximum_bytes=6)
    with pytest.raises(ConfigurationError, match="^configuration_structure_too_large$"):
        parse_config_json(b'{"nested":' + b"[" * 65 + b"0" + b"]" * 65 + b"}")


def test_small_elements_cannot_exceed_the_structure_node_budget():
    raw = b'{"items":[' + b",".join([b"0"] * 100_001) + b"]}"
    with pytest.raises(ConfigurationError, match="^configuration_structure_too_large$"):
        parse_config_json(raw)


@pytest.mark.parametrize("value", [True, 0, -1, 2 * 1024 * 1024, "1024"])
def test_parser_does_not_accept_an_unbounded_caller_limit(value):
    with pytest.raises(ConfigurationError, match="^configuration_limit_invalid$"):
        parse_config_json(b"{}", maximum_bytes=value)

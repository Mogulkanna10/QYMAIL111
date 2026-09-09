import pytest
from backend.crypto import serialization


def test_serialize_dict_is_deterministic():
    """Edge case: serializing the same dict twice must produce byte-identical output."""
    obj = {"session_id": b"\x01" * 16, "ts": 12345, "label": "test"}
    result1 = serialization.serialize(obj)
    result2 = serialization.serialize(obj)
    assert result1 == result2


def test_serialize_bytes_as_hex():
    """Happy path: bytes fields are encoded as lowercase hex strings."""
    obj = {"key": b"\xde\xad\xbe\xef"}
    result = serialization.serialize(obj)
    assert b'"deadbeef"' in result


def test_serialize_dict_keys_sorted():
    """Edge case: key order in input dict must not affect output (keys are sorted)."""
    obj_a = {"z_field": 1, "a_field": 2}
    obj_b = {"a_field": 2, "z_field": 1}
    assert serialization.serialize(obj_a) == serialization.serialize(obj_b)


def test_serialize_no_whitespace():
    """Edge case: output must have no unnecessary whitespace (compact JSON)."""
    obj = {"field": "value"}
    result = serialization.serialize(obj)
    assert b" " not in result


def test_serialize_unsupported_type_raises():
    """Tamper path: non-serializable types must raise an error."""
    obj = {"bad": object()}
    with pytest.raises(TypeError):
        serialization.serialize(obj)

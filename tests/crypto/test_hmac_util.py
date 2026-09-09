import pytest
from backend.crypto import hmac_util


def test_hmac_compute_produces_bytes():
    """Happy path: compute returns non-empty bytes."""
    tag = hmac_util.compute(b"key", b"message")
    assert isinstance(tag, bytes)
    assert len(tag) > 0


def test_hmac_verify_valid():
    """Happy path: verify returns True for a valid tag."""
    tag = hmac_util.compute(b"key", b"message")
    assert hmac_util.verify(b"key", b"message", tag) is True


def test_hmac_verify_wrong_key():
    """Tamper path: verify returns False with a wrong key."""
    tag = hmac_util.compute(b"key", b"message")
    assert hmac_util.verify(b"wrong-key", b"message", tag) is False


def test_hmac_verify_wrong_data():
    """Tamper path: verify returns False with tampered data."""
    tag = hmac_util.compute(b"key", b"message")
    assert hmac_util.verify(b"key", b"tampered message", tag) is False


def test_hmac_deterministic():
    """Edge case: same key and data always produce same tag."""
    tag1 = hmac_util.compute(b"k", b"data")
    tag2 = hmac_util.compute(b"k", b"data")
    assert tag1 == tag2

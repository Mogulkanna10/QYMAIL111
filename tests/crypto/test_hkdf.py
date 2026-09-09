import pytest
from backend.crypto import hkdf


def test_extract_produces_bytes():
    """Happy path: extract returns non-empty bytes."""
    prk = hkdf.extract(b"salt", b"input key material")
    assert isinstance(prk, bytes)
    assert len(prk) > 0


def test_expand_produces_correct_length():
    """Happy path: expand returns exactly the requested number of bytes."""
    prk = hkdf.extract(b"salt", b"ikm")
    key = hkdf.expand(prk, b"QYMail-SessionKey-v1", 32)
    assert len(key) == 32


def test_labels_produce_distinct_keys():
    """Edge case: distinct labels from PROTOCOL_SPEC.md must produce different outputs."""
    prk = hkdf.extract(b"", b"shared_secret_material")
    tk = hkdf.expand(prk, hkdf.LABEL_TK, 32)
    kwrap_c = hkdf.expand(prk, hkdf.LABEL_KWRAP_C, 32)
    kwrap_s = hkdf.expand(prk, hkdf.LABEL_KWRAP_S, 32)
    sk = hkdf.expand(prk, hkdf.LABEL_SESSION_KEY, 32)
    # All four must be different from each other
    assert len({tk, kwrap_c, kwrap_s, sk}) == 4, "HKDF labels must produce distinct keys"


def test_extract_deterministic():
    """Edge case: same inputs always produce same PRK."""
    prk1 = hkdf.extract(b"salt", b"ikm")
    prk2 = hkdf.extract(b"salt", b"ikm")
    assert prk1 == prk2


def test_expand_different_info_differs():
    """Tamper path: different info produces different expanded output."""
    prk = hkdf.extract(b"salt", b"ikm")
    key1 = hkdf.expand(prk, b"label-one", 32)
    key2 = hkdf.expand(prk, b"label-two", 32)
    assert key1 != key2

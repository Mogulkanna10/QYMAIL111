import pytest
from backend.crypto import sha3


def test_sha3_256_known_output():
    """Happy path: SHA3-256 of empty bytes must produce a known digest."""
    result = sha3.hash256(b"")
    # SHA3-256("") is a known constant
    expected = bytes.fromhex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
    assert result == expected


def test_sha3_256_produces_32_bytes():
    """Happy path: output must always be 32 bytes."""
    result = sha3.hash256(b"QYMail test data")
    assert len(result) == 32


def test_sha3_256_deterministic():
    """Edge case: same input must always produce same output."""
    data = b"deterministic input"
    assert sha3.hash256(data) == sha3.hash256(data)


def test_sha3_256_different_inputs_differ():
    """Edge case: different inputs must produce different digests."""
    assert sha3.hash256(b"input A") != sha3.hash256(b"input B")

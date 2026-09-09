import pytest
import os
from backend.crypto import commitment


SESSION_ID = b"\x01" * 16


def test_commit_produces_32_bytes():
    """Happy path: commitment output must be 32 bytes."""
    tef = os.urandom(32)
    r = os.urandom(16)
    c = commitment.commit(tef, r, SESSION_ID)
    assert len(c) == 32


def test_verify_commitment_valid():
    """Happy path: verify_commitment returns True for correct inputs."""
    tef = os.urandom(32)
    r = os.urandom(16)
    c = commitment.commit(tef, r, SESSION_ID)
    assert commitment.verify_commitment(c, tef, r, SESSION_ID) is True


def test_verify_commitment_wrong_tef():
    """Tamper path: wrong TEF must return False, not raise."""
    tef = os.urandom(32)
    r = os.urandom(16)
    c = commitment.commit(tef, r, SESSION_ID)
    wrong_tef = os.urandom(32)
    assert commitment.verify_commitment(c, wrong_tef, r, SESSION_ID) is False


def test_verify_commitment_wrong_nonce():
    """Tamper path: wrong nonce (r) must return False, not raise."""
    tef = os.urandom(32)
    r = os.urandom(16)
    c = commitment.commit(tef, r, SESSION_ID)
    wrong_r = os.urandom(16)
    assert commitment.verify_commitment(c, tef, wrong_r, SESSION_ID) is False


def test_verify_commitment_wrong_session_id():
    """Tamper path: wrong session_id must return False, not raise."""
    tef = os.urandom(32)
    r = os.urandom(16)
    c = commitment.commit(tef, r, SESSION_ID)
    wrong_sid = b"\x02" * 16
    assert commitment.verify_commitment(c, tef, r, wrong_sid) is False


def test_commitment_deterministic():
    """Edge case: same inputs always produce same commitment."""
    tef = b"\xab" * 32
    r = b"\xcd" * 16
    assert commitment.commit(tef, r, SESSION_ID) == commitment.commit(tef, r, SESSION_ID)

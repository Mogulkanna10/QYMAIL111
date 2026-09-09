"""
R2 — Canonical serialization determinism test for real M1-M6 message types.

Guarantees that calling serialize() on the same M-class instance twice produces
byte-identical output.  This is the same guarantee Stage 2 proved for plain dicts;
this file extends it to the actual protocol message types the TAKD-PQE handshake uses.

Global Rule R2 requires that no two serializations of the same logical message
ever differ — this test mechanically enforces that guarantee.
"""
import os
import pytest
from backend.crypto.serialization import serialize
from backend.protocol.messages import M1, M2, M3, M4, M5, M6


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


# ─── M2: primary required test (cited in remediation directive) ───────────────

def test_m2_canonical_serialization_is_deterministic():
    """
    Serialize the same M2 instance twice via serialize() and assert byte-identical
    output.  This is the specific test required by Stage 4 Remediation Item R2.
    """
    instance = M2(
        session_id=_random_bytes(16),
        ct=_random_bytes(1568),
        CommitC=_random_bytes(32),
    )
    first  = serialize(instance)
    second = serialize(instance)
    assert first == second, (
        "serialize(M2) produced different bytes on two calls to the same instance — "
        "canonical serialization is broken"
    )


# ─── All message types: determinism ──────────────────────────────────────────

def test_m1_canonical_serialization_is_deterministic():
    instance = M1(
        session_id=_random_bytes(16),
        TS=1_700_000_000,
        pkS=_random_bytes(1568),
        quote={
            "device_id": "test-device",
            "firmware_hash": _random_bytes(32).hex(),
            "ephemeral_kem_public_key": _random_bytes(32).hex(),
            "session_id": _random_bytes(16).hex(),
            "timestamp": 1_700_000_000,
        },
        SigS=_random_bytes(4627),
    )
    assert serialize(instance) == serialize(instance)


def test_m3_canonical_serialization_is_deterministic():
    instance = M3(
        CommitS=_random_bytes(32),
        MAC1=_random_bytes(32),
    )
    assert serialize(instance) == serialize(instance)


def test_m4_canonical_serialization_is_deterministic():
    instance = M4(wrappedC=_random_bytes(64))
    assert serialize(instance) == serialize(instance)


def test_m5_canonical_serialization_is_deterministic():
    instance = M5(
        wrappedS=_random_bytes(64),
        MACS=_random_bytes(32),
    )
    assert serialize(instance) == serialize(instance)


def test_m6_canonical_serialization_is_deterministic():
    instance = M6(MACC=_random_bytes(32))
    assert serialize(instance) == serialize(instance)


# ─── M2: cross-instance equality with identical content ──────────────────────

def test_m2_identical_content_produces_identical_bytes():
    """Two distinct M2 instances with the same field values serialize identically."""
    sid = _random_bytes(16)
    ct  = _random_bytes(1568)
    cc  = _random_bytes(32)
    a = M2(session_id=sid, ct=ct, CommitC=cc)
    b = M2(session_id=sid, ct=ct, CommitC=cc)
    assert serialize(a) == serialize(b), (
        "Two M2 instances with identical content produced different serializations — "
        "canonical serialization is not stable across instances"
    )


# ─── M2: differing content produces differing bytes ──────────────────────────

def test_m2_different_content_produces_different_bytes():
    """Sanity-check: changing a field must change the serialized output."""
    sid = _random_bytes(16)
    ct  = _random_bytes(1568)
    a = M2(session_id=sid, ct=ct, CommitC=_random_bytes(32))
    b = M2(session_id=sid, ct=ct, CommitC=_random_bytes(32))
    # With overwhelming probability the two random CommitC values differ
    assert serialize(a) != serialize(b), (
        "Two M2 instances with different CommitC produced identical serializations — "
        "the encoder is ignoring field content"
    )


# ─── Serialization path: confirm .to_dict() branch is taken ──────────────────

def test_m2_uses_to_dict_branch(monkeypatch):
    """
    Confirm serialize() dispatches through the .to_dict() code path for M-class
    instances (stdlib @dataclass, not Pydantic BaseModel).
    """
    instance = M2(
        session_id=_random_bytes(16),
        ct=_random_bytes(1568),
        CommitC=_random_bytes(32),
    )
    called = []
    original_to_dict = instance.to_dict

    def patched_to_dict():
        called.append(True)
        return original_to_dict()

    monkeypatch.setattr(instance, "to_dict", patched_to_dict)
    serialize(instance)
    assert called, (
        "serialize() did not call .to_dict() on an M2 instance — "
        "the dispatch path for @dataclass message types is broken"
    )

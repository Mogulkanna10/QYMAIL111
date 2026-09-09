"""
Tests for backend/shm/software_shm.py and backend/shm/zeroization.py
"""

import pytest
import os
from backend.shm.software_shm import SoftwareSHM
from backend.shm import zeroization
from backend.crypto import dsa


@pytest.fixture
def shm():
    return SoftwareSHM()


# --- generate_tef ---

def test_generate_tef_lengths(shm):
    """Happy path: TEF is 32 bytes, r is 16 bytes."""
    session_id = os.urandom(16)
    tef, r = shm.generate_tef(session_id)
    assert len(tef) == 32
    assert len(r) == 16


def test_generate_tef_distinct_on_each_call(shm):
    """Edge case: consecutive TEF samples must differ."""
    sid = os.urandom(16)
    tef1, _ = shm.generate_tef(sid)
    tef2, _ = shm.generate_tef(sid)
    assert tef1 != tef2


def test_generate_tef_passes_health_test(shm):
    """Happy path: TEF output passes the health test (os.urandom is good entropy)."""
    sid = os.urandom(16)
    tef, _ = shm.generate_tef(sid)
    assert shm.health_test(tef) is True


# --- health_test ---

def test_health_test_fails_zeros(shm):
    """Bad entropy: all-zero 32-byte sample must fail health test."""
    assert shm.health_test(b"\x00" * 32) is False


def test_health_test_passes_urandom(shm):
    """Good entropy: os.urandom(64) must pass health test."""
    assert shm.health_test(os.urandom(64)) is True


# --- generate_kem_keypair ---

def test_generate_kem_keypair_sizes(shm):
    """Happy path: ML-KEM-1024 public key is 1568 bytes."""
    pk, sk = shm.generate_kem_keypair()
    assert len(pk) == 1568
    assert len(sk) > 0


# --- attestation via shm ---

def test_shm_sign_and_verify_attestation(shm):
    """Happy path: attestation sign+verify round trip via SoftwareSHM."""
    signing_pk, signing_sk = dsa.generate_keypair()
    pk, _ = shm.generate_kem_keypair()
    sid = os.urandom(16)
    quote = shm.get_attestation_quote(
        device_id=shm.device_id,
        firmware_hash=shm.firmware_hash,
        ephemeral_kem_public_key=pk,
        session_id=sid,
        timestamp=9999999,
    )
    sig = shm.sign_attestation(quote, signing_sk)

    from backend.shm.attestation import verify_quote
    assert verify_quote(quote, sig, signing_pk) is True


def test_shm_attestation_tampered_key_rejected(shm):
    """Tamper path: modified ephemeral key in quote must fail verification."""
    signing_pk, signing_sk = dsa.generate_keypair()
    pk, _ = shm.generate_kem_keypair()
    sid = os.urandom(16)
    quote = shm.get_attestation_quote(
        device_id=shm.device_id,
        firmware_hash=shm.firmware_hash,
        ephemeral_kem_public_key=pk,
        session_id=sid,
        timestamp=9999999,
    )
    sig = shm.sign_attestation(quote, signing_sk)

    tampered_pk = bytearray(pk)
    tampered_pk[42] ^= 0xAB
    quote["ephemeral_kem_public_key"] = bytes(tampered_pk)

    from backend.shm.attestation import verify_quote
    assert verify_quote(quote, sig, signing_pk) is False


# --- secure_store and zeroize ---

def test_secure_store_and_retrieve(shm):
    """Happy path: store and key is present in internal store."""
    shm.secure_store("test_key", b"super secret")
    assert "test_key" in shm._store


def test_zeroize_removes_key(shm):
    """Happy path: after zeroize, key no longer present in store."""
    shm.secure_store("secret", b"data")
    shm.zeroize("secret")
    assert "secret" not in shm._store


def test_zeroize_bytearray_overwrites():
    """Edge case: zeroize_bytearray sets all bytes to 0."""
    buf = bytearray(b"\xff\xfe\xfd\xfc")
    zeroization.zeroize_bytearray(buf)
    assert all(b == 0 for b in buf)


def test_zeroize_missing_key_no_error(shm):
    """Edge case: zeroizing a non-existent key must not raise."""
    shm.zeroize("non_existent_key")  # should not raise


# --- R3: SoftwareSHM label check ---

def test_software_shm_label_in_module_docstring():
    """R3 compliance: module docstring must contain 'EMULATION' label."""
    import backend.shm.software_shm as m
    assert "EMULATION" in (m.__doc__ or ""), "SoftwareSHM module must be labeled as software emulation"


def test_zeroization_label_in_module_docstring():
    """R3 compliance: zeroization module docstring must contain limitation label."""
    import backend.shm.zeroization as z
    assert "BEST-EFFORT" in (z.__doc__ or ""), "Zeroization module must document its software-only limitation"

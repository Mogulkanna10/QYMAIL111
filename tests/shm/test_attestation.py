"""
Tests for backend/shm/attestation.py
"""

import pytest
import os
from backend.crypto import dsa
from backend.shm import attestation


SESSION_ID = os.urandom(16)
FIRMWARE_HASH = os.urandom(32)
PK_DUMMY = os.urandom(1568)


def _make_quote(pk=None, sid=None):
    return attestation.build_quote(
        device_id="test-device",
        firmware_hash=FIRMWARE_HASH,
        ephemeral_kem_public_key=pk or PK_DUMMY,
        session_id=sid or SESSION_ID,
        timestamp=1234567890,
    )


def test_attestation_sign_and_verify_valid():
    """Happy path: sign a quote and verify it succeeds."""
    signing_pk, signing_sk = dsa.generate_keypair()
    quote = _make_quote()
    sig = attestation.sign_quote(quote, signing_sk)
    assert attestation.verify_quote(quote, sig, signing_pk) is True


def test_attestation_tampered_ephemeral_key_fails():
    """Tamper path: flipping a byte in ephemeral_kem_public_key invalidates the signature."""
    signing_pk, signing_sk = dsa.generate_keypair()
    quote = _make_quote()
    sig = attestation.sign_quote(quote, signing_sk)

    # Build a new quote with a different ephemeral public key — same signature
    tampered_pk = bytearray(PK_DUMMY)
    tampered_pk[0] ^= 0xFF
    tampered_quote = _make_quote(pk=bytes(tampered_pk))

    assert attestation.verify_quote(tampered_quote, sig, signing_pk) is False


def test_attestation_tampered_signature_fails():
    """Tamper path: flipping a byte in the signature itself must fail verification."""
    signing_pk, signing_sk = dsa.generate_keypair()
    quote = _make_quote()
    sig = bytearray(attestation.sign_quote(quote, signing_sk))
    sig[0] ^= 0xFF
    assert attestation.verify_quote(quote, bytes(sig), signing_pk) is False


def test_attestation_wrong_pk_fails():
    """Tamper path: verifying with a different public key must fail."""
    _, signing_sk = dsa.generate_keypair()
    wrong_pk, _ = dsa.generate_keypair()
    quote = _make_quote()
    sig = attestation.sign_quote(quote, signing_sk)
    assert attestation.verify_quote(quote, sig, wrong_pk) is False


def test_attestation_quote_fields():
    """Edge case: built quote contains all required fields."""
    quote = _make_quote()
    assert "device_id" in quote
    assert "firmware_hash" in quote
    assert "ephemeral_kem_public_key" in quote
    assert "session_id" in quote
    assert "timestamp" in quote

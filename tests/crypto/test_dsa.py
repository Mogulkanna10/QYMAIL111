import pytest
from backend.crypto import dsa


def test_dsa_keypair_generation():
    """Happy path: generate keypair and check expected types."""
    pk, sk = dsa.generate_keypair()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    assert len(pk) > 0
    assert len(sk) > 0


def test_dsa_sign_and_verify_valid():
    """Happy path: sign a message and verify the signature returns True."""
    pk, sk = dsa.generate_keypair()
    msg = b"This is the test message for signing"
    sig = dsa.sign(sk, msg)
    assert dsa.verify(pk, msg, sig) is True


def test_dsa_tampered_message_fails():
    """Tamper path: tampered message must fail verification (return False)."""
    pk, sk = dsa.generate_keypair()
    msg = b"Original message"
    sig = dsa.sign(sk, msg)
    result = dsa.verify(pk, b"Tampered message", sig)
    assert result is False, "Tampered message must not verify"


def test_dsa_tampered_signature_fails():
    """Tamper path: tampered signature must fail verification."""
    pk, sk = dsa.generate_keypair()
    msg = b"Original message"
    sig = bytearray(dsa.sign(sk, msg))
    sig[0] ^= 0xFF  # flip byte
    result = dsa.verify(pk, msg, bytes(sig))
    assert result is False, "Tampered signature must not verify"


def test_dsa_wrong_pk_fails():
    """Tamper path: verifying with a different public key must fail."""
    pk1, sk1 = dsa.generate_keypair()
    pk2, _ = dsa.generate_keypair()
    msg = b"Test message"
    sig = dsa.sign(sk1, msg)
    result = dsa.verify(pk2, msg, sig)
    assert result is False, "Wrong public key must not verify"

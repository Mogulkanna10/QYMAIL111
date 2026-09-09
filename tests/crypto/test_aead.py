import pytest
import os
from backend.crypto import aead
from backend.crypto.aead import AEADAuthError


def test_encrypt_decrypt_roundtrip():
    """Happy path: decrypt(encrypt(plaintext)) == plaintext."""
    key = os.urandom(32)
    plaintext = b"Hello, QYMail!"
    ad = b"associated data"
    ct = aead.encrypt(key, plaintext, ad)
    recovered = aead.decrypt(key, ct, ad)
    assert recovered == plaintext


def test_tampered_ciphertext_raises_aead_auth_error():
    """Tamper path: flipping a byte in ciphertext raises AEADAuthError."""
    key = os.urandom(32)
    ct = aead.encrypt(key, b"secret", b"ad")
    tampered = bytearray(ct)
    tampered[-1] ^= 0x01
    with pytest.raises(AEADAuthError, match="AEAD authentication tag verification failed"):
        aead.decrypt(key, bytes(tampered), b"ad")


def test_wrong_associated_data_raises_aead_auth_error():
    """Tamper path: wrong AD must cause AEAD authentication failure."""
    key = os.urandom(32)
    ct = aead.encrypt(key, b"secret", b"original-ad")
    with pytest.raises(AEADAuthError):
        aead.decrypt(key, ct, b"different-ad")


def test_wrong_key_raises_aead_auth_error():
    """Tamper path: wrong decryption key must raise AEADAuthError."""
    key = os.urandom(32)
    wrong_key = os.urandom(32)
    ct = aead.encrypt(key, b"secret", b"ad")
    with pytest.raises(AEADAuthError):
        aead.decrypt(wrong_key, ct, b"ad")


def test_ciphertext_too_short_raises():
    """Edge case: ciphertext shorter than nonce must raise AEADAuthError."""
    key = os.urandom(32)
    with pytest.raises(AEADAuthError, match="too short"):
        aead.decrypt(key, b"short", b"ad")

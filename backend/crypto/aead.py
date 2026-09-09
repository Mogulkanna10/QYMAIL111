from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
import os

class AEADAuthError(Exception):
    pass

def encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """
    Encrypts plaintext using ChaCha20-Poly1305. 
    The nonce is generated internally and prepended to the ciphertext.
    Returns: nonce (12 bytes) || ciphertext
    """
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = chacha.encrypt(nonce, plaintext, associated_data)
    return nonce + ct

def decrypt(key: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    """
    Decrypts a ChaCha20-Poly1305 ciphertext (nonce || ct).
    Raises AEADAuthError on authentication failure.
    """
    if len(ciphertext) < 12:
        raise AEADAuthError("Ciphertext too short (missing nonce)")
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    chacha = ChaCha20Poly1305(key)
    try:
        return chacha.decrypt(nonce, ct, associated_data)
    except InvalidTag:
        raise AEADAuthError("AEAD authentication tag verification failed")

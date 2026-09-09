from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# HKDF label constants matching PROTOCOL_SPEC.md exactly
LABEL_TK = b"QYMail-TK-v1"
LABEL_KWRAP_C = b"QYMail-KwrapC-v1"
LABEL_KWRAP_S = b"QYMail-KwrapS-v1"
LABEL_SESSION_KEY = b"QYMail-SessionKey-v1"

def extract(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF-Extract step. Mathematically identical to HMAC-Hash(salt, ikm).
    If salt is empty or None, it defaults to a string of HashLen zeros.
    """
    if not salt:
        salt = b'\x00' * 48 # SHA3-384 length
    h = hmac.HMAC(salt, hashes.SHA3_384())
    h.update(ikm)
    return h.finalize()

def expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand step."""
    hkdf = HKDFExpand(
        algorithm=hashes.SHA3_384(),
        length=length,
        info=info,
    )
    return hkdf.derive(prk)

from cryptography.hazmat.primitives import hashes, hmac
import hmac as std_hmac

def compute(key: bytes, data: bytes) -> bytes:
    """Computes HMAC-SHA384 of the data using the key."""
    h = hmac.HMAC(key, hashes.SHA3_384())
    h.update(data)
    return h.finalize()

def verify(key: bytes, data: bytes, tag: bytes) -> bool:
    """Verifies HMAC-SHA384 tag in constant time."""
    expected = compute(key, data)
    return std_hmac.compare_digest(expected, tag)

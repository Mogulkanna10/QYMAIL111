from cryptography.hazmat.primitives import hashes

def hash256(data: bytes) -> bytes:
    """Computes SHA3-256 of the given data."""
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(data)
    return digest.finalize()

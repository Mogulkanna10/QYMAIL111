import oqs

def generate_keypair() -> tuple[bytes, bytes]:
    """Generates an ML-DSA-87 keypair. Returns (public_key, secret_key)."""
    with oqs.Signature('ML-DSA-87') as signer:
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
        return pk, sk

def sign(sk: bytes, msg: bytes) -> bytes:
    """Signs a message using the given secret key. Returns the signature."""
    with oqs.Signature('ML-DSA-87', secret_key=sk) as signer:
        return signer.sign(msg)

def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Verifies a signature. Returns True if valid, False otherwise."""
    with oqs.Signature('ML-DSA-87') as verifier:
        try:
            result = verifier.verify(msg, sig, pk)
            return bool(result)
        except Exception:
            return False

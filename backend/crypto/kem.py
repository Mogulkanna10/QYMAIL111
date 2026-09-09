import oqs

def generate_keypair() -> tuple[bytes, bytes]:
    """Generates an ML-KEM-1024 keypair. Returns (public_key, secret_key)."""
    with oqs.KeyEncapsulation('ML-KEM-1024') as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        return pk, sk

def encapsulate(pk: bytes) -> tuple[bytes, bytes]:
    """Encapsulates a secret to the given public key. Returns (ciphertext, shared_secret)."""
    with oqs.KeyEncapsulation('ML-KEM-1024') as kem:
        return kem.encap_secret(pk)

def decapsulate(sk: bytes, ct: bytes) -> bytes:
    """Decapsulates a KEM ciphertext using the secret key. Returns shared_secret."""
    with oqs.KeyEncapsulation('ML-KEM-1024', secret_key=sk) as kem:
        return kem.decap_secret(ct)

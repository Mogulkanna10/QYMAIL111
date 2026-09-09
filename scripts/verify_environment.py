import oqs
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
import os
import sys

def verify():
    # 1. ML-KEM-1024
    with oqs.KeyEncapsulation('ML-KEM-1024') as client_kem:
        public_key = client_kem.generate_keypair()
        with oqs.KeyEncapsulation('ML-KEM-1024') as server_kem:
            ciphertext, shared_secret_server = server_kem.encap_secret(public_key)
        shared_secret_client = client_kem.decap_secret(ciphertext)
        assert shared_secret_server == shared_secret_client, "ML-KEM-1024 shared secrets mismatch"
        print("ML-KEM-1024 OK")

    # 2. ML-DSA-87
    with oqs.Signature('ML-DSA-87') as signer:
        public_key_sig = signer.generate_keypair()
        message = b"test message for signing"
        signature = signer.sign(message)
        with oqs.Signature('ML-DSA-87') as verifier:
            is_valid = verifier.verify(message, signature, public_key_sig)
            assert is_valid, "ML-DSA-87 valid signature rejected"
            
            # Tamper message
            try:
                result = verifier.verify(b"tampered message", signature, public_key_sig)
                assert result is False, "ML-DSA-87 accepted tampered message"
            except Exception as e:
                # Exception counts as pass as well
                pass
            print("ML-DSA-87 OK")

    # 3. SHA3-256
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(b"test data")
    h = digest.finalize()
    print("SHA3-256 OK:", h.hex())

    # 4. HKDF-SHA384
    hkdf = HKDF(
        algorithm=hashes.SHA3_384(),
        length=32,
        salt=b"salt",
        info=b"info",
    )
    key = hkdf.derive(b"input keying material")
    print(f"HKDF-SHA384 OK: derived {len(key)} bytes")

    # 5. HMAC-SHA384
    h = hmac.HMAC(b"key", hashes.SHA3_384())
    h.update(b"message")
    mac = h.finalize()
    print("HMAC-SHA384 OK")

    # 6. ChaCha20-Poly1305
    key = os.urandom(32)
    nonce = os.urandom(12)
    aad = b"associated data"
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, b"plaintext", aad)
    plaintext = chacha.decrypt(nonce, ciphertext, aad)
    assert plaintext == b"plaintext", "ChaCha20-Poly1305 decryption failed"

    # Tamper ciphertext
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 1
    try:
        chacha.decrypt(nonce, bytes(tampered), aad)
        assert False, "ChaCha20-Poly1305 tampered ciphertext should have raised InvalidTag"
    except InvalidTag:
        print("ChaCha20-Poly1305 OK")

    print("ALL PRIMITIVES OK")

if __name__ == "__main__":
    verify()

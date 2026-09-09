import pytest
from backend.crypto import kem


def test_kem_keypair_generation():
    """Happy path: generate a keypair and check expected sizes."""
    pk, sk = kem.generate_keypair()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    assert len(pk) == 1568  # ML-KEM-1024 public key size
    assert len(sk) > 0


def test_kem_encapsulate_decapsulate_shared_secret_match():
    """Happy path: shared secrets from encapsulate and decapsulate must be byte-identical."""
    pk, sk = kem.generate_keypair()
    ct, ss_server = kem.encapsulate(pk)
    ss_client = kem.decapsulate(sk, ct)
    assert ss_server == ss_client, "Shared secrets must be byte-identical"
    assert len(ss_server) == 32  # ML-KEM-1024 shared secret size


def test_kem_ciphertext_size():
    """Edge case: KEM ciphertext must be exactly 1568 bytes."""
    pk, _ = kem.generate_keypair()
    ct, _ = kem.encapsulate(pk)
    assert len(ct) == 1568  # ML-KEM-1024 ciphertext size


def test_kem_wrong_sk_produces_different_secret():
    """Tamper path: decapsulating with a different secret key produces a different (wrong) secret."""
    pk1, sk1 = kem.generate_keypair()
    pk2, sk2 = kem.generate_keypair()
    ct, ss_correct = kem.encapsulate(pk1)
    # ML-KEM is designed to always decapsulate without error (implicit rejection),
    # but the resulting shared secret will differ from the correct one.
    ss_wrong = kem.decapsulate(sk2, ct)
    assert ss_correct != ss_wrong, "Wrong SK should produce a different shared secret"


def test_kem_fresh_keypairs_differ():
    """Edge case: two freshly generated keypairs must not be identical."""
    pk1, sk1 = kem.generate_keypair()
    pk2, sk2 = kem.generate_keypair()
    assert pk1 != pk2
    assert sk1 != sk2

"""M4: Client → Server — build and verify. PROTOCOL_SPEC.md §2 M4."""
from backend.protocol.messages import M4
from backend.protocol.errors import AEADError, CommitmentError
from backend.protocol.key_schedule import derive_kwrap_c
from backend.crypto.aead import encrypt, decrypt
from backend.crypto.aead import AEADAuthError
from backend.crypto.commitment import verify_commitment


def build_m4(ss: bytes, tefc: bytes, rc: bytes, th3: bytes) -> M4:
    """Client builds M4: AEAD-wraps TEFC||rC under Kwrap,C with AD=TH3."""
    kwrap_c = derive_kwrap_c(ss)
    wrapped = encrypt(kwrap_c, tefc + rc, th3)
    return M4(wrappedC=wrapped)


def verify_m4(m4: M4, ss: bytes, commit_c: bytes, session_id: bytes, th3: bytes) -> tuple[bytes, bytes]:
    """
    Server verifies M4: decrypts wrappedC, checks commitment binding.
    Returns (tefc, rc) on success. Raises on any failure.
    """
    kwrap_c = derive_kwrap_c(ss)
    try:
        plaintext = decrypt(kwrap_c, m4.wrappedC, th3)
    except AEADAuthError as e:
        raise AEADError(f"M4: AEAD authentication tag verification failed: {e}") from e
    if len(plaintext) != 48:  # 32 (TEFC) + 16 (rC)
        raise AEADError("M4: decrypted payload has unexpected length")
    tefc, rc = plaintext[:32], plaintext[32:]
    if not verify_commitment(commit_c, tefc, rc, session_id):
        raise CommitmentError("M4: TEFC||rC reveal does not match CommitC — binding check failed")
    return tefc, rc

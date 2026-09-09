"""M5: Server → Client — build and verify. PROTOCOL_SPEC.md §2 M5.

DECISIONS.md:
  - AD for wrappedS = TH4 (consistency with M4's "AD = transcript hash at prior message").
  - TH5 = SHA3-256(TH4 || canonical({wrappedS})) — MACS cannot cover itself.
  - MACS = HMAC(SessionKey, "confirm-S" || TH5).
"""
from backend.crypto.sha3 import hash256
from backend.crypto.serialization import serialize
from backend.protocol.messages import M5
from backend.protocol.errors import AEADError, CommitmentError, MACError
from backend.protocol.key_schedule import derive_kwrap_s, derive_session_key
from backend.protocol.fusion import compute_fusion
from backend.crypto.aead import encrypt, decrypt
from backend.crypto.aead import AEADAuthError
from backend.crypto.commitment import verify_commitment
from backend.crypto import hmac_util


def build_m5(ss: bytes, tefs: bytes, rs: bytes, tefc: bytes, session_id: bytes, th4: bytes) -> tuple[M5, bytes, bytes, bytes]:
    """
    Server builds M5: wraps TEFS||rS, derives SessionKey, computes MACS.
    Returns (M5, fusion, session_key, th5).
    """
    kwrap_s = derive_kwrap_s(ss)
    wrapped_s = encrypt(kwrap_s, tefs + rs, th4)

    fusion = compute_fusion(tefc, tefs, session_id)
    session_key = derive_session_key(ss, fusion)

    # TH5 covers M5-minus-MACS so MACS doesn't hash itself
    th5 = hash256(th4 + serialize({"wrappedS": wrapped_s}))
    macs = hmac_util.compute(session_key, b"confirm-S" + th5)

    return M5(wrappedS=wrapped_s, MACS=macs), fusion, session_key, th5


def verify_m5(m5: M5, ss: bytes, commit_s: bytes, session_id: bytes, th4: bytes, tefc: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Client verifies M5: decrypts wrappedS, checks commitment, derives SessionKey, verifies MACS.
    Returns (session_key, fusion, th5).
    """
    kwrap_s = derive_kwrap_s(ss)
    try:
        plaintext = decrypt(kwrap_s, m5.wrappedS, th4)
    except AEADAuthError as e:
        raise AEADError(f"M5: AEAD authentication tag verification failed: {e}") from e
    if len(plaintext) != 48:
        raise AEADError("M5: decrypted payload has unexpected length")
    tefs, rs = plaintext[:32], plaintext[32:]

    if not verify_commitment(commit_s, tefs, rs, session_id):
        raise CommitmentError("M5: TEFS||rS reveal does not match CommitS — binding check failed")

    fusion = compute_fusion(tefc, tefs, session_id)
    session_key = derive_session_key(ss, fusion)

    # Recompute TH5 same way server did
    th5 = hash256(th4 + serialize({"wrappedS": m5.wrappedS}))
    if not hmac_util.verify(session_key, b"confirm-S" + th5, m5.MACS):
        raise MACError("M5: MACS key-confirmation failed — SessionKey mismatch or tampering")

    return session_key, fusion, th5

"""M6: Client → Server — build and verify. PROTOCOL_SPEC.md §2 M6.

DECISIONS.md: TH6 = SHA3-256(TH5 || canonical(M5_full)) where M5_full includes MACS.
              MACC = HMAC(SessionKey, "confirm-C" || TH6).
"""
from backend.crypto.sha3 import hash256
from backend.crypto.serialization import serialize
from backend.protocol.messages import M5, M6
from backend.protocol.errors import MACError
from backend.crypto import hmac_util


def build_m6(session_key: bytes, m5: M5, th5: bytes) -> tuple[M6, bytes]:
    """Client builds M6. TH6 covers the full M5 (including MACS). Returns (M6, th6)."""
    th6 = hash256(th5 + serialize(m5.to_dict()))
    macc = hmac_util.compute(session_key, b"confirm-C" + th6)
    return M6(MACC=macc), th6


def verify_m6(m6: M6, session_key: bytes, m5: M5, th5: bytes) -> bytes:
    """Server verifies MACC. Returns th6 on success. Raises MACError on failure."""
    th6 = hash256(th5 + serialize(m5.to_dict()))
    if not hmac_util.verify(session_key, b"confirm-C" + th6, m6.MACC):
        raise MACError("M6: MACC key-confirmation failed — client SessionKey mismatch or tampering")
    return th6

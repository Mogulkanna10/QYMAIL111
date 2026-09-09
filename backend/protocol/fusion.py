"""Fusion computation — PROTOCOL_SPEC.md §6."""
from backend.crypto.sha3 import hash256


def compute_fusion(tefc: bytes, tefs: bytes, session_id: bytes) -> bytes:
    """
    Fusion = SHA3-256(TEFC || TEFS || session_id)
    Never transmitted on the wire — both sides derive independently.
    """
    return hash256(tefc + tefs + session_id)

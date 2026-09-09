"""M3: Server → Client — build and verify. PROTOCOL_SPEC.md §2 M3.

DECISIONS.md: TK = HKDF-Expand(HKDF-Extract(salt=b'', ikm=ss), info=b'QYMail-TK-v1', length=32).
Derived from ss only — Fusion not yet available (TEFs not yet revealed).
"""
from backend.protocol.messages import M3
from backend.protocol.errors import MACError
from backend.crypto.commitment import commit
from backend.crypto.kem import decapsulate
from backend.protocol.key_schedule import derive_tk
from backend.crypto import hmac_util


def build_m3(session_id: bytes, ct: bytes, sk_s: bytes, th2: bytes, shm) -> tuple[M3, bytes, bytes, bytes, bytes]:
    """
    Server builds M3: decapsulates ss, generates TEFS/rS, derives TK, computes MAC1.
    Returns (M3, ss, tefs, rs, tk).
    """
    ss = decapsulate(sk_s, ct)
    tefs, rs = shm.generate_tef(session_id)
    commit_s = commit(tefs, rs, session_id)
    tk = derive_tk(ss)
    mac1 = hmac_util.compute(tk, b"commit" + th2)
    return M3(CommitS=commit_s, MAC1=mac1), ss, tefs, rs, tk


def verify_m3(m3: M3, ss: bytes, th2: bytes) -> None:
    """Client verifies MAC1 using its own ss. Raises MACError on failure."""
    tk = derive_tk(ss)
    if not hmac_util.verify(tk, b"commit" + th2, m3.MAC1):
        raise MACError("M3: MAC1 key-possession proof failed — possible impersonation")

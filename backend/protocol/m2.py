"""M2: Client → Server — build and verify. PROTOCOL_SPEC.md §2 M2.

Structural commit-before-reveal guarantee: CommitC is computed here using only
material the client already holds (TEFC, rC, session_id from M1).  It has ZERO
dependency on CommitS (which the server sends in M3, received later).  This is the
structural enforcement of bias-resistance per Theorem 4 of the paper.
"""
from backend.protocol.messages import M2
from backend.protocol.errors import SessionIDMismatch
from backend.crypto.commitment import commit
from backend.crypto.kem import encapsulate


def build_m2(session_id: bytes, pkS: bytes, shm) -> tuple[M2, bytes, bytes, bytes]:
    """
    Client builds M2.
    Returns (M2, ct, ss, tefc, rc) — ss/tefc/rc are ephemeral secrets kept by the client.
    NOTE: CommitC is computed before the client can possibly know CommitS (M3 not yet received).
    """
    ct, ss = encapsulate(pkS)
    tefc, rc = shm.generate_tef(session_id)
    commit_c = commit(tefc, rc, session_id)
    m2 = M2(session_id=session_id, ct=ct, CommitC=commit_c)
    return m2, ct, ss, tefc, rc


def verify_m2(m2: M2, expected_session_id: bytes) -> None:
    """Server verifies M2 session_id binding. Raises on mismatch."""
    if m2.session_id != expected_session_id:
        raise SessionIDMismatch("M2: session_id mismatch")

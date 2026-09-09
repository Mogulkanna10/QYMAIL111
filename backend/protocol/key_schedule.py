"""
HKDF key schedule — PROTOCOL_SPEC.md §3.

All labels match the HKDF Label Registry exactly.
Decision log (DECISIONS.md):
  - TK, KwrapC, KwrapS: extracted from ss alone (Fusion not yet available at M3/M4).
  - SessionKey: extracted from ss, salted by Fusion (paper: "keyed by ss and salted with Fusion").
"""
from backend.crypto.hkdf import extract, expand, LABEL_TK, LABEL_KWRAP_C, LABEL_KWRAP_S, LABEL_SESSION_KEY

KEY_LEN = 32  # bytes — all derived keys are 256-bit


def derive_tk(ss: bytes) -> bytes:
    """TK = HKDF-Expand(HKDF-Extract(salt=b'', ikm=ss), info=LABEL_TK, length=32)"""
    prk = extract(b"", ss)
    return expand(prk, LABEL_TK, KEY_LEN)


def derive_kwrap_c(ss: bytes) -> bytes:
    """Kwrap,C = HKDF-Expand(HKDF-Extract(salt=b'', ikm=ss), info=LABEL_KWRAP_C, length=32)"""
    prk = extract(b"", ss)
    return expand(prk, LABEL_KWRAP_C, KEY_LEN)


def derive_kwrap_s(ss: bytes) -> bytes:
    """Kwrap,S = HKDF-Expand(HKDF-Extract(salt=b'', ikm=ss), info=LABEL_KWRAP_S, length=32)"""
    prk = extract(b"", ss)
    return expand(prk, LABEL_KWRAP_S, KEY_LEN)


def derive_session_key(ss: bytes, fusion: bytes) -> bytes:
    """
    PRK = HKDF-Extract(salt=Fusion, ikm=ss)
    SessionKey = HKDF-Expand(PRK, info=LABEL_SESSION_KEY, length=32)
    """
    prk = extract(fusion, ss)
    return expand(prk, LABEL_SESSION_KEY, KEY_LEN)

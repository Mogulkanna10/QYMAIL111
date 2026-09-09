from backend.crypto.sha3 import hash256

def commit(tef: bytes, r: bytes, session_id: bytes) -> bytes:
    """Computes a SHA3-256 commitment of TEF, nonce (r), and session_id."""
    return hash256(tef + r + session_id)

def verify_commitment(commitment: bytes, tef: bytes, r: bytes, session_id: bytes) -> bool:
    """Verifies that the given parameters hash to the expected commitment."""
    expected = commit(tef, r, session_id)
    return commitment == expected

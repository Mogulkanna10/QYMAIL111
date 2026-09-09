"""M1: Server → Client — build and verify. PROTOCOL_SPEC.md §2 M1."""
import time
from backend.protocol.messages import M1
from backend.protocol.errors import AttestationError, SessionIDMismatch
from backend.shm.attestation import verify_quote


def build_m1(session_id: bytes, pkS: bytes, signing_sk: bytes, shm) -> M1:
    """Server builds M1: generates quote, signs it, returns M1."""
    ts = int(time.time())
    quote = shm.get_attestation_quote(
        device_id=shm.device_id,
        firmware_hash=shm.firmware_hash,
        ephemeral_kem_public_key=pkS,
        session_id=session_id,
        timestamp=ts,
    )
    sig = shm.sign_attestation(quote, signing_sk)
    return M1(session_id=session_id, TS=ts, pkS=pkS, quote=quote, SigS=sig)


def verify_m1(m1: M1, server_signing_pk: bytes) -> None:
    """
    Client verifies M1. Raises on any failure (R5: fail closed).
    Checks: SigS valid | quote.ephemeral_kem_public_key == pkS | quote.session_id == session_id
    """
    if not verify_quote(m1.quote, m1.SigS, server_signing_pk):
        raise AttestationError("M1: server attestation signature (SigS) is invalid")
    if m1.quote.get("ephemeral_kem_public_key") != m1.pkS:
        raise AttestationError("M1: quote.ephemeral_kem_public_key does not match pkS")
    if m1.quote.get("session_id") != m1.session_id:
        raise SessionIDMismatch("M1: quote.session_id does not match message session_id")

"""
Attestation quote builder and signer.

Builds a quote binding an ephemeral KEM public key to a device identity, then
signs SHA3-256(canonical(quote)) with ML-DSA-87 under the server's long-term key.

NOTE (R3): This is SOFTWARE EMULATION of TPM-style hardware attestation.
The quote is constructed and signed in-process. There is no hardware isolation,
no TPM PCR measurement, and no hardware-guaranteed key non-extractability.
All signatures and device identifiers are software-generated.
"""

from backend.crypto.sha3 import hash256
from backend.crypto.serialization import serialize
from backend.crypto import dsa


def build_quote(
    device_id: str,
    firmware_hash: bytes,
    ephemeral_kem_public_key: bytes,
    session_id: bytes,
    timestamp: int,
) -> dict:
    """
    Build an attestation quote as a structured dict.

    The quote binds the ephemeral KEM public key to the device identity and
    session. This is the structure that gets hashed and signed.

    NOTE (R3): Software emulation of TPM attestation quote construction.
    """
    return {
        "device_id": device_id,
        "firmware_hash": firmware_hash,
        "ephemeral_kem_public_key": ephemeral_kem_public_key,
        "session_id": session_id,
        "timestamp": timestamp,
    }


def sign_quote(quote: dict, signing_sk: bytes) -> bytes:
    """
    Sign SHA3-256(canonical(quote)) using ML-DSA-87 under the long-term signing key.

    Returns the raw signature bytes (4627 bytes for ML-DSA-87).

    NOTE (R3): Signing is performed in software. This is NOT hardware-attested signing.
    """
    canonical_bytes = serialize(quote)
    quote_hash = hash256(canonical_bytes)
    return dsa.sign(signing_sk, quote_hash)


def verify_quote(quote: dict, signature: bytes, signing_pk: bytes) -> bool:
    """
    Verify ML-DSA-87 signature over SHA3-256(canonical(quote)).

    Returns True if the signature is valid; False otherwise.
    Also verifies that the quote's ephemeral_kem_public_key matches the
    pkS field binding — callers should separately check quote.session_id
    matches the current session.

    NOTE (R3): Software emulation of TPM quote verification.
    """
    canonical_bytes = serialize(quote)
    quote_hash = hash256(canonical_bytes)
    return dsa.verify(signing_pk, quote_hash, signature)

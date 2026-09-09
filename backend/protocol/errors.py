"""
Protocol-level error types. All failures raise a specific subclass (R5: fail closed).
Error messages must be non-secret-leaking — never include key material.
"""


class ProtocolError(Exception):
    """Base class for all TAKD-PQE protocol violations."""
    pass


class AttestationError(ProtocolError):
    """M1 attestation signature invalid or quote binding check failed."""
    pass


class CommitmentError(ProtocolError):
    """Commitment reveal does not match the earlier commitment."""
    pass


class MACError(ProtocolError):
    """HMAC key-confirmation tag verification failed."""
    pass


class AEADError(ProtocolError):
    """AEAD decryption or authentication tag failure."""
    pass


class SessionIDMismatch(ProtocolError):
    """session_id in message does not match the established session."""
    pass

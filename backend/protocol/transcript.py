"""Transcript hash chain — PROTOCOL_SPEC.md §4."""
from backend.crypto.sha3 import hash256
from backend.crypto.serialization import serialize


_INIT_PREFIX = b"QYMail-init"


class TranscriptManager:
    """
    Maintains TH0..TH6 per PROTOCOL_SPEC.md §4:
        TH0 = SHA3-256("QYMail-init" || session_id)
        THi = SHA3-256(TH(i-1) || canonical(Mi))
    """

    def __init__(self, session_id: bytes):
        self._th = hash256(_INIT_PREFIX + session_id)
        self._index = 0

    @property
    def current(self) -> bytes:
        return self._th

    def update(self, message) -> bytes:
        """Hash canonical(message) into the running chain and return new TH."""
        self._th = hash256(self._th + serialize(message.to_dict()))
        self._index += 1
        return self._th

    def update_partial(self, partial_dict: dict) -> bytes:
        """
        Hash a partial dict (e.g. M5-minus-MACS) into the chain.
        Used for TH5 computation where MACS must not cover itself.
        """
        self._th = hash256(self._th + serialize(partial_dict))
        self._index += 1
        return self._th

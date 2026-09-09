"""
Wire-format serialization / deserialization for M1-M6.

serialize_message(msg) -> bytes
    Converts any M1-M6 object to canonical JSON bytes using the existing
    backend.crypto.serialization.serialize() function.

deserialize_<Mx>(data: bytes) -> Mx
    Parses canonical JSON bytes back into the corresponding message object.
    bytes fields are stored as hex strings on the wire and restored here.

The deserializer for each message must know the expected type in advance —
this is fine because the protocol state machine dictates exactly which message
type each party expects to receive next (PROTOCOL_SPEC.md §2, §8).
"""

import json

from backend.crypto.serialization import serialize
from backend.protocol.messages import M1, M2, M3, M4, M5, M6


# ─── Serialization ────────────────────────────────────────────────────────────

def serialize_message(msg) -> bytes:
    """Canonical wire encoding for any M1-M6 message object → JSON bytes."""
    return serialize(msg.to_dict())


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _h(val: str) -> bytes:
    """Decode a hex string from the JSON wire representation back to bytes."""
    return bytes.fromhex(val)


# ─── Deserializers ────────────────────────────────────────────────────────────

def deserialize_m1(data: bytes) -> M1:
    """
    Parse M1 wire bytes back to an M1 object.

    M1 bytes fields: session_id, pkS, SigS.
    Nested in quote: firmware_hash, ephemeral_kem_public_key, session_id.
    """
    d = json.loads(data)
    q = d["quote"]
    quote = {
        "device_id":              q["device_id"],
        "firmware_hash":          _h(q["firmware_hash"]),
        "ephemeral_kem_public_key": _h(q["ephemeral_kem_public_key"]),
        "session_id":             _h(q["session_id"]),
        "timestamp":              q["timestamp"],
    }
    return M1(
        session_id=_h(d["session_id"]),
        TS=d["TS"],
        pkS=_h(d["pkS"]),
        quote=quote,
        SigS=_h(d["SigS"]),
    )


def deserialize_m2(data: bytes) -> M2:
    """Parse M2 wire bytes → M2. bytes fields: session_id, ct, CommitC."""
    d = json.loads(data)
    return M2(
        session_id=_h(d["session_id"]),
        ct=_h(d["ct"]),
        CommitC=_h(d["CommitC"]),
    )


def deserialize_m3(data: bytes) -> M3:
    """Parse M3 wire bytes → M3. bytes fields: CommitS, MAC1."""
    d = json.loads(data)
    return M3(
        CommitS=_h(d["CommitS"]),
        MAC1=_h(d["MAC1"]),
    )


def deserialize_m4(data: bytes) -> M4:
    """Parse M4 wire bytes → M4. bytes fields: wrappedC."""
    d = json.loads(data)
    return M4(wrappedC=_h(d["wrappedC"]))


def deserialize_m5(data: bytes) -> M5:
    """Parse M5 wire bytes → M5. bytes fields: wrappedS, MACS."""
    d = json.loads(data)
    return M5(
        wrappedS=_h(d["wrappedS"]),
        MACS=_h(d["MACS"]),
    )


def deserialize_m6(data: bytes) -> M6:
    """Parse M6 wire bytes → M6. bytes fields: MACC."""
    d = json.loads(data)
    return M6(MACC=_h(d["MACC"]))

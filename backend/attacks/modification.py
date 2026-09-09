"""
Attack: In-Flight Message Modification (M4 ciphertext tampering).

The attacker intercepts M4 (Client → Server: wrappedC) while it is in
transit through the NetworkSimulator queue and flips bit 0 of the
ciphertext blob before it reaches the server.

Defense caught
--------------
backend.protocol.errors.AEADError
  → m4.verify_m4: "M4: AEAD authentication tag verification failed"
  ← ChaCha20-Poly1305 authentication fails because the tag was computed
     over the *original* ciphertext; any mutation makes it invalid.

Paper mapping
-------------
G8 (Transcript Integrity) — THREAT_MODEL.md §4
PROTOCOL_SPEC.md §2 M4: wrappedC = ChaCha20-Poly1305(Kwrap,C,
  TEFC||rC, AD=TH3).  The AEAD tag covers the entire ciphertext; a
  single bit flip is detectable with overwhelming probability.

How the attack runs
-------------------
1. Start a live handshake via the simulator with an active modify hook
   that mutates the first alice→bob message (M4) by flipping byte 0.
2. The server's verify_m4() calls decrypt(Kwrap_C, mutated_wrappedC, TH3)
   → ChaCha20-Poly1305 raises AEADAuthError → wrapped as AEADError.
3. The handshake aborts; the server's thread collects the error.
"""

from backend.attacks._harness import AttackResult, make_endpoints, run_live_handshake
from backend.protocol.errors import AEADError

# Track which message index is alice→bob so we can target M4 specifically.
# Message order alice→bob: M2 (index 0), M4 (index 1), M6 (index 2).
_M4_ALICE_TO_BOB_INDEX = 1


def _flip_byte_zero(data: bytes) -> bytes:
    """Flip all bits in byte 0 of the payload."""
    ba = bytearray(data)
    ba[0] ^= 0xFF
    return bytes(ba)


def run() -> AttackResult:
    """
    Flip a byte in M4's wrappedC in transit. Assert AEADError is raised.
    """
    _, alice, bob, sim, attacker = make_endpoints()

    # Counter: track which alice→bob message we have seen.
    state = {"alice_to_bob_count": 0, "m4_mutated": False, "original_len": 0, "mutated_len": 0}

    def _modify_m4(sf, st, data, sim_ref):
        if sf == "alice" and st == "bob":
            idx = state["alice_to_bob_count"]
            state["alice_to_bob_count"] += 1
            if idx == _M4_ALICE_TO_BOB_INDEX:
                import json
                from backend.crypto.serialization import serialize
                state["original_len"] = len(data)
                
                d = json.loads(data)
                wrapped_c_bytes = bytes.fromhex(d["wrappedC"])
                mutated_wrapped_c = _flip_byte_zero(wrapped_c_bytes)
                d["wrappedC"] = mutated_wrapped_c.hex()
                mutated = serialize(d)
                
                state["mutated_len"] = len(mutated)
                state["m4_mutated"] = True
                return mutated
        return data

    attacker._add_hook(_modify_m4)
    errors = run_live_handshake(sim, attacker, alice, bob)

    bob_errors = [e for role, e in errors if role == "bob"]
    aead_error = next((e for e in bob_errors if isinstance(e, AEADError)), None)

    if aead_error:
        return AttackResult(
            attack_name="modification",
            blocked=True,
            failure_reason=f"AEADError raised by verify_m4: \"{aead_error}\"",
            raw_evidence={
                "attack_message": "M4",
                "mutated_field": "wrappedC (byte 0 flipped: XOR 0xFF)",
                "defense_invariant": "G8 Transcript Integrity (THREAT_MODEL.md §4)",
                "protocol_check": "m4.verify_m4: ChaCha20-Poly1305 authentication tag",
                "m4_mutated": state["m4_mutated"],
                "original_payload_len_bytes": state["original_len"],
            },
        )
    else:
        return AttackResult(
            attack_name="modification",
            blocked=False,
            failure_reason="AEADError was NOT raised — attack succeeded",
            raw_evidence={
                "bob_errors": [str(e) for e in bob_errors],
                "m4_mutated": state["m4_mutated"],
            },
        )

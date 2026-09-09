"""
Attack: Forged Attestation (Ephemeral KEM Key Substitution).

The attacker intercepts M1 (Server → Client) in transit and replaces the
ephemeral KEM public key (pkS) with an attacker-generated key, while leaving
the attestation signature SigS unchanged (they do not hold the server's
long-term signing key, so they cannot produce a valid signature over the
substituted key).

Defense caught
--------------
backend.protocol.errors.AttestationError
  → m1.verify_m1: "M1: server attestation signature (SigS) is invalid"
  ← ML-DSA-87 verify_quote returns False because SigS was produced over
     the *original* pkS; the substituted key produces a different digest.

Paper mapping
-------------
G2 (Mutual Authentication) — THREAT_MODEL.md §4
PROTOCOL_SPEC.md §2 M1: SigS = ML-DSA-87.Sign(skS,
  SHA3-256(device_id || firmware_hash || pkS || session_id || TS)).
  The signature covers pkS; any substitution is detectable unless the
  attacker also holds skS (EUF-CMA security of ML-DSA-87).

How the attack runs
-------------------
1. Intercept M1 bytes off the simulator queue (alice's inbound queue).
2. Deserialize M1, generate an attacker-controlled KEM keypair, replace
   msg.pkS with the attacker pk, re-serialize.
3. Deliver the modified M1 bytes to Alice.
4. Alice's process_m1() calls verify_m1() → verify_quote() → ML-DSA-87
   verify returns False → AttestationError raised.
"""

import json

from backend.attacks._harness import AttackResult, make_endpoints, run_live_handshake
from backend.crypto.kem import generate_keypair as kem_keypair
from backend.crypto.serialization import serialize
from backend.network.wire import deserialize_m1
from backend.protocol.errors import AttestationError


def _substitute_pks(m1_bytes: bytes) -> bytes:
    """
    Replace pkS in the serialized M1 JSON with an attacker-generated KEM pk.
    Also replaces it inside the quote to bypass structural checks and force
    a signature verification failure.
    SigS is left unchanged — attacker cannot re-sign without the server's skS.
    Returns the re-serialized M1 bytes.
    """
    d = json.loads(m1_bytes)
    attacker_pk, _ = kem_keypair()
    d["pkS"] = attacker_pk.hex()          # substitute in root
    d["quote"]["ephemeral_kem_public_key"] = attacker_pk.hex()  # substitute in quote
    # Re-serialize with the canonical serializer (sort_keys, no spaces)
    return serialize(d)


def run() -> AttackResult:
    """
    Substitute pkS in M1 in transit. Assert AttestationError is raised by Alice.
    """
    _, alice, bob, sim, attacker = make_endpoints()

    # Track whether we actually mutated M1
    state = {"m1_mutated": False, "original_pks_len": 0}

    def _forge_m1(sf, st, data, sim_ref):
        """Intercept the first bob→alice message (M1) and forge pkS."""
        if sf == "bob" and st == "alice" and not state["m1_mutated"]:
            state["m1_mutated"] = True
            original = json.loads(data)
            state["original_pks_len"] = len(bytes.fromhex(original["pkS"]))
            return _substitute_pks(data)
        return data

    attacker._add_hook(_forge_m1)
    errors = run_live_handshake(sim, attacker, alice, bob)

    alice_errors = [e for role, e in errors if role == "alice"]
    attest_error = next((e for e in alice_errors if isinstance(e, AttestationError)), None)

    if attest_error:
        return AttackResult(
            attack_name="forged_attestation",
            blocked=True,
            failure_reason=f"AttestationError raised by verify_m1: \"{attest_error}\"",
            raw_evidence={
                "attack_message": "M1",
                "mutated_field": "pkS (replaced with attacker-generated ML-KEM-1024 pk)",
                "sigs_changed": False,
                "defense_invariant": "G2 Mutual Authentication (THREAT_MODEL.md §4)",
                "protocol_check": "m1.verify_m1: ML-DSA-87 signature covers pkS",
                "original_pks_len_bytes": state["original_pks_len"],
                "m1_mutated": state["m1_mutated"],
            },
        )
    else:
        return AttackResult(
            attack_name="forged_attestation",
            blocked=False,
            failure_reason="AttestationError was NOT raised — attack succeeded",
            raw_evidence={
                "alice_errors": [str(e) for e in alice_errors],
                "m1_mutated": state["m1_mutated"],
            },
        )

#!/usr/bin/env python3
"""
QYMail-TEF TAKD-PQE Handshake CLI — Stage 6 Network Simulator Edition.

Architecture change vs Stage 4:
  - Alice (client) and Bob (server) each run in their own thread.
  - They communicate ONLY through NetworkSimulator.send() / .receive().
  - There are NO direct python function calls from alice's thread to bob's
    thread or vice versa — only serialized bytes transit the simulator queue.
  - Attacker is attached but idle (zero hooks active), so behaviour must be
    identical to Stage 4.

Wire format: backend.network.wire.serialize_message / deserialize_<Mx>()
Messages on the queue: canonical JSON bytes (UTF-8), fields hex-encoded.

Run: PYTHONPATH=/path/to/QYMAIL python scripts/run_handshake_cli.py
"""

import sys
import os
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.crypto.dsa import generate_keypair as dsa_keypair
from backend.protocol.session import HandshakeSession
from backend.protocol.state_machine import SessionRole, SessionState
from backend.network.simulator import NetworkSimulator
from backend.network.attacker import Attacker
from backend.network.wire import (
    serialize_message,
    deserialize_m1, deserialize_m2, deserialize_m3,
    deserialize_m4, deserialize_m5, deserialize_m6,
)


# ─── Thread entry points ──────────────────────────────────────────────────────

def bob_thread(
    bob: HandshakeSession,
    sim: NetworkSimulator,
    errors: list,
):
    """
    Bob (server) thread.

    Sends/receives only through NetworkSimulator.  Zero direct calls to Alice.
    Message sequence: create M1 → send → recv M2 → send M3 → recv M4 →
                      send M5 → recv M6 → ESTABLISHED.
    """
    try:
        # M1: Bob → Alice
        m1 = bob.create_m1()
        sim.send("bob", "alice", serialize_message(m1))

        # M2: Alice → Bob
        m2 = deserialize_m2(sim.receive("bob"))
        m3 = bob.process_m2(m2)
        sim.send("bob", "alice", serialize_message(m3))

        # M4: Alice → Bob
        m4 = deserialize_m4(sim.receive("bob"))
        m5 = bob.process_m4(m4)
        sim.send("bob", "alice", serialize_message(m5))

        # M6: Alice → Bob
        m6 = deserialize_m6(sim.receive("bob"))
        bob.process_m6(m6)

    except Exception as exc:
        errors.append(("bob", exc))


def alice_thread(
    alice: HandshakeSession,
    sim: NetworkSimulator,
    errors: list,
):
    """
    Alice (client) thread.

    Sends/receives only through NetworkSimulator.  Zero direct calls to Bob.
    Message sequence: recv M1 → send M2 → recv M3 → send M4 → recv M5 →
                      send M6 → ESTABLISHED.
    """
    try:
        # M1: Bob → Alice
        m1 = deserialize_m1(sim.receive("alice"))
        m2 = alice.process_m1(m1)
        sim.send("alice", "bob", serialize_message(m2))

        # M3: Bob → Alice
        m3 = deserialize_m3(sim.receive("alice"))
        m4 = alice.process_m3(m3)
        sim.send("alice", "bob", serialize_message(m4))

        # M5: Bob → Alice
        m5 = deserialize_m5(sim.receive("alice"))
        m6 = alice.process_m5(m5)
        sim.send("alice", "bob", serialize_message(m6))

    except Exception as exc:
        errors.append(("alice", exc))


# ─── Main ─────────────────────────────────────────────────────────────────────

def run_handshake():
    print("=== QYMail-TEF TAKD-PQE Handshake CLI (Stage 6 — Network Simulator) ===\n")
    print("Transport: NetworkSimulator (in-process queue, canonical JSON wire bytes)")
    print("Attacker:  attached, zero hooks active (pass-through)\n")

    # Long-term server signing keypair (pre-provisioned)
    server_pk, server_sk = dsa_keypair()

    # Independent session objects — they never call each other directly
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)

    # Simulator + attacker (idle)
    sim      = NetworkSimulator()
    attacker = Attacker()
    sim.register("alice")
    sim.register("bob")
    sim.set_attacker(attacker)   # no hooks → pure pass-through

    # Thread error collector
    errors: list = []

    # Spawn threads — Bob must send M1 first so start him slightly before Alice
    t_bob   = threading.Thread(target=bob_thread,   args=(bob,   sim, errors), daemon=True)
    t_alice = threading.Thread(target=alice_thread, args=(alice, sim, errors), daemon=True)

    t_bob.start()
    t_alice.start()

    t_bob.join(timeout=30)
    t_alice.join(timeout=30)

    # Surface any thread-internal exceptions
    if errors:
        for role, exc in errors:
            print(f"ERROR in {role} thread: {type(exc).__name__}: {exc}")
        sys.exit(1)

    if t_bob.is_alive() or t_alice.is_alive():
        print("ERROR: handshake threads did not complete within timeout — possible deadlock")
        sys.exit(1)

    # ── Post-handshake assertions ──────────────────────────────────────────

    print("M1 OK  (server → client: pkS + attestation quote + SigS)")
    print("M2 OK  (client → server: KEM ciphertext + CommitC)")
    print("M3 OK  (server → client: CommitS + MAC1)")
    print("M4 OK  (client → server: wrappedC reveal)")
    print("M5 OK  (server → client: wrappedS reveal + MACS)")
    print("M6 OK  (client → server: MACC)\n")

    print("=== SESSION ESTABLISHED ===")
    print(f"Alice state : {alice.session_state.value}")
    print(f"Bob   state : {bob.session_state.value}")

    assert alice.session_key == bob.session_key, "FATAL: session keys do not match!"
    print(f"\nAlice SessionKey[:8]: {alice.session_key.hex()[:16]}...")
    print(f"Bob   SessionKey[:8]: {bob.session_key.hex()[:16]}...")
    print("Alice.SessionKey == Bob.SessionKey: TRUE")

    assert alice.session_state == SessionState.ESTABLISHED
    assert bob.session_state == SessionState.ESTABLISHED
    print("Both endpoints in state ESTABLISHED: TRUE")

    # Simulator introspection — prove real bytes went through the queue
    total_messages = len(attacker.captured)
    total_bytes    = sum(len(b) for _, _, b in attacker.captured)
    print(f"\nSimulator captured {total_messages} messages ({total_bytes} bytes total)")
    print("All checks passed.")


if __name__ == "__main__":
    run_handshake()

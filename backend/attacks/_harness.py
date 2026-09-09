"""
Attack harness — shared live-handshake runner for Stage 7 attack modules.

Provides:
  AttackResult — the uniform return type for all attack modules.
  run_live_handshake() — spins a full M1-M6 handshake through the
      NetworkSimulator with a real Attacker attached, returning the
      endpoint objects and any per-thread errors collected.

ARCHITECTURE NOTE: Alice and Bob are independent HandshakeSession objects
communicating only through the NetworkSimulator queue (ARCHITECTURE.md §2).
No direct cross-endpoint calls are made here or in any attack module.
"""

import threading
from dataclasses import dataclass, field

from backend.crypto.dsa import generate_keypair as dsa_keypair
from backend.protocol.session import HandshakeSession
from backend.protocol.state_machine import SessionRole
from backend.network.simulator import NetworkSimulator
from backend.network.attacker import Attacker
from backend.network.wire import (
    serialize_message,
    deserialize_m1, deserialize_m2, deserialize_m3,
    deserialize_m4, deserialize_m5, deserialize_m6,
)


# ─── AttackResult ─────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    """
    Uniform return type for all Stage 7 attack modules.

    Fields:
        attack_name     : human-readable name of the attack
        blocked         : True if the protocol rejected the attack
        failure_reason  : the specific exception message or structural
                          argument that blocked it (non-empty when blocked=True)
        raw_evidence    : safe-to-display metadata about the attack run —
                          MUST NOT contain any secret field (ss, TEF*, sk, SessionKey)
    """
    attack_name: str
    blocked: bool
    failure_reason: str
    raw_evidence: dict = field(default_factory=dict)


# ─── Shared harness ───────────────────────────────────────────────────────────

def make_endpoints(shm_alice=None, shm_bob=None):
    """
    Create fresh, independent server/client HandshakeSession objects and
    a new simulator+attacker.  Returns (server_pk, alice, bob, sim, attacker).

    shm_alice / shm_bob: optional custom SoftwareSHM instances (used by
    entropy_failure.py to inject a poisoned SHM into Alice's session).
    """
    server_pk, server_sk = dsa_keypair()

    kwargs_bob = dict(role=SessionRole.SERVER,
                      server_signing_sk=server_sk,
                      server_signing_pk=server_pk)
    kwargs_alice = dict(role=SessionRole.CLIENT, server_signing_pk=server_pk)

    if shm_bob is not None:
        kwargs_bob["shm"] = shm_bob
    if shm_alice is not None:
        kwargs_alice["shm"] = shm_alice

    bob = HandshakeSession(**kwargs_bob)
    alice = HandshakeSession(**kwargs_alice)

    sim = NetworkSimulator()
    attacker = Attacker()
    sim.register("alice")
    sim.register("bob")
    sim.set_attacker(attacker)

    return server_pk, alice, bob, sim, attacker


def _bob_thread(bob, sim, errors):
    """Bob (server) thread — communicates only through the simulator."""
    try:
        m1 = bob.create_m1()
        sim.send("bob", "alice", serialize_message(m1))

        m2 = deserialize_m2(sim.receive("bob", timeout=10.0))
        m3 = bob.process_m2(m2)
        sim.send("bob", "alice", serialize_message(m3))

        m4 = deserialize_m4(sim.receive("bob", timeout=10.0))
        m5 = bob.process_m4(m4)
        sim.send("bob", "alice", serialize_message(m5))

        m6 = deserialize_m6(sim.receive("bob", timeout=10.0))
        bob.process_m6(m6)
    except Exception as exc:
        errors.append(("bob", exc))


def _alice_thread(alice, sim, errors):
    """Alice (client) thread — communicates only through the simulator."""
    try:
        m1 = deserialize_m1(sim.receive("alice", timeout=10.0))
        m2 = alice.process_m1(m1)
        sim.send("alice", "bob", serialize_message(m2))

        m3 = deserialize_m3(sim.receive("alice", timeout=10.0))
        m4 = alice.process_m3(m3)
        sim.send("alice", "bob", serialize_message(m4))

        m5 = deserialize_m5(sim.receive("alice", timeout=10.0))
        m6 = alice.process_m5(m5)
        sim.send("alice", "bob", serialize_message(m6))
    except Exception as exc:
        errors.append(("alice", exc))


def run_live_handshake(sim, attacker, alice, bob, timeout=15.0):
    """
    Spin alice and bob in separate threads through the given simulator.
    Returns the errors list — non-empty means at least one endpoint raised.

    The attacker's hooks are already registered on sim before this call;
    callers set up hooks before calling this function.
    """
    errors = []
    t_bob   = threading.Thread(target=_bob_thread,   args=(bob,   sim, errors), daemon=True)
    t_alice = threading.Thread(target=_alice_thread, args=(alice, sim, errors), daemon=True)
    t_bob.start()
    t_alice.start()
    t_bob.join(timeout=timeout)
    t_alice.join(timeout=timeout)
    return errors

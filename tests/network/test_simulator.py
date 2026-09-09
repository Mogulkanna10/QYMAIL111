"""
Stage 6 — Network Simulator Tests.

Tests each of the six attacker primitives independently on real message bytes
flowing through the NetworkSimulator queue.  Every test:
  1. Runs an actual handshake (or partial handshake) to produce real wire bytes.
  2. Applies one specific primitive.
  3. Asserts the observable effect on delivery.

No synthetic/mocked message bytes are used.  The bytes under test are always
the canonical JSON output of backend.network.wire.serialize_message() as
captured from the simulator's Attacker.captured list.

Run:
  PYTHONPATH=/home/mogul/Downloads/QYMAIL \\
    venv/bin/python -m pytest tests/network/ -v \\
    --override-ini="addopts="
"""

import os
import threading
import time
import pytest

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
from backend.protocol.errors import (
    MACError, AEADError, CommitmentError, SessionIDMismatch, AttestationError
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def keypair():
    return dsa_keypair()


def _make_sim():
    sim      = NetworkSimulator()
    attacker = Attacker()
    sim.register("alice")
    sim.register("bob")
    sim.set_attacker(attacker)
    return sim, attacker


def _bob_thread(bob, sim, errors):
    try:
        m1 = bob.create_m1()
        sim.send("bob", "alice", serialize_message(m1))
        m2 = deserialize_m2(sim.receive("bob"))
        m3 = bob.process_m2(m2)
        sim.send("bob", "alice", serialize_message(m3))
        m4 = deserialize_m4(sim.receive("bob"))
        m5 = bob.process_m4(m4)
        sim.send("bob", "alice", serialize_message(m5))
        m6 = deserialize_m6(sim.receive("bob"))
        bob.process_m6(m6)
    except Exception as exc:
        errors.append(("bob", exc))


def _alice_thread(alice, sim, errors):
    try:
        m1 = deserialize_m1(sim.receive("alice"))
        m2 = alice.process_m1(m1)
        sim.send("alice", "bob", serialize_message(m2))
        m3 = deserialize_m3(sim.receive("alice"))
        m4 = alice.process_m3(m3)
        sim.send("alice", "bob", serialize_message(m4))
        m5 = deserialize_m5(sim.receive("alice"))
        m6 = alice.process_m5(m5)
        sim.send("alice", "bob", serialize_message(m6))
    except Exception as exc:
        errors.append(("alice", exc))


def _run_full_handshake(keypair):
    """Utility: complete handshake through the simulator, return (alice, bob, sim, attacker)."""
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    sim, attacker = _make_sim()
    errors = []

    t_bob   = threading.Thread(target=_bob_thread,   args=(bob,   sim, errors), daemon=True)
    t_alice = threading.Thread(target=_alice_thread, args=(alice, sim, errors), daemon=True)
    t_bob.start(); t_alice.start()
    t_bob.join(timeout=30); t_alice.join(timeout=30)

    assert not errors,      f"Handshake thread errors: {errors}"
    assert not t_bob.is_alive() and not t_alice.is_alive(), "Threads did not complete"
    return alice, bob, sim, attacker


# ═══════════════════════════════════════════════════════════════════════════════
# Primitive 1 — delay
# Assert: message still arrives, but delivery takes at least `ms` milliseconds.
# ═══════════════════════════════════════════════════════════════════════════════

def test_delay_holds_message_in_transit(keypair):
    """
    delay(ms) must cause each message to take at least `ms` milliseconds to
    arrive at the recipient.  We use a short delay (50 ms) to keep the test fast.
    The elapsed time is measured using monotonic clock around a single send/receive
    pair using a simple push-pull setup (no full handshake needed).
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    sim, attacker = _make_sim()

    # Produce real M1 bytes
    m1_bytes = serialize_message(bob.create_m1())

    DELAY_MS = 50
    with attacker.delay(DELAY_MS):
        t0 = time.monotonic()
        sim.send("bob", "alice", m1_bytes)
        received = sim.receive("alice", timeout=5.0)
        elapsed_ms = (time.monotonic() - t0) * 1000

    # Message must still arrive and be identical
    assert received == m1_bytes, "delay must not corrupt message bytes"
    assert elapsed_ms >= DELAY_MS * 0.9, (
        f"delay primitive did not hold message long enough: {elapsed_ms:.1f} ms < {DELAY_MS} ms"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Primitive 2 — drop
# Assert: message never arrives at recipient (TimeoutError within timeout).
# ═══════════════════════════════════════════════════════════════════════════════

def test_drop_prevents_delivery(keypair):
    """
    drop() must cause the message to never reach the recipient.
    We attempt to receive with a short timeout and expect TimeoutError.
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    sim, attacker = _make_sim()

    m1_bytes = serialize_message(bob.create_m1())

    with attacker.drop():
        sim.send("bob", "alice", m1_bytes)

    # Queue should be empty — receive must time out
    with pytest.raises(TimeoutError):
        sim.receive("alice", timeout=0.2)


# ═══════════════════════════════════════════════════════════════════════════════
# Primitive 3 — duplicate
# Assert: recipient queue contains two identical copies after one send().
# ═══════════════════════════════════════════════════════════════════════════════

def test_duplicate_delivers_extra_copies(keypair):
    """
    duplicate() must enqueue extra_copies additional copies of the message.
    We use extra_copies=1 (→ 2 copies total) and assert both are identical
    and byte-for-byte equal to the original.
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    sim, attacker = _make_sim()

    m1_bytes = serialize_message(bob.create_m1())

    with attacker.duplicate(extra_copies=1):
        sim.send("bob", "alice", m1_bytes)

    copy1 = sim.receive("alice", timeout=1.0)
    copy2 = sim.receive("alice", timeout=1.0)

    assert copy1 == m1_bytes, "first copy must match original bytes"
    assert copy2 == m1_bytes, "duplicate copy must match original bytes"

    # No third copy should exist
    with pytest.raises(TimeoutError):
        sim.receive("alice", timeout=0.2)


# ═══════════════════════════════════════════════════════════════════════════════
# Primitive 4 — reorder
# Assert: messages arrive in the caller-supplied order, not send() order.
# ═══════════════════════════════════════════════════════════════════════════════

def test_reorder_changes_delivery_sequence(keypair):
    """
    reorder() injects a list of bytes into the destination queue in the
    caller-specified order.  We capture M1 and M3 bytes (the two server→client
    messages), then reorder them (M3 before M1) and verify the queue delivers
    M3 first.

    Note: we produce M1 and M3 via a partial handshake.  The messages are real
    wire bytes but we inject them out-of-order directly via reorder() and verify
    the queue order — we do NOT attempt to complete a handshake with reordered
    messages (that would correctly fail at the protocol layer, which is Stage 7's
    job).
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    sim, attacker = _make_sim()

    # Produce M1 and M3 via partial handshake (normal order through a temp sim)
    temp_sim, _ = _make_sim()
    m1_obj = bob.create_m1()
    m1_bytes = serialize_message(m1_obj)
    m2 = alice.process_m1(m1_obj)
    m3_bytes = serialize_message(bob.process_m2(m2))

    # Inject in reversed order: M3 first, then M1
    attacker.reorder([m3_bytes, m1_bytes], sid_to="alice", simulator=sim)

    first  = sim.receive("alice", timeout=1.0)
    second = sim.receive("alice", timeout=1.0)

    assert first  == m3_bytes, "reorder must deliver M3 first"
    assert second == m1_bytes, "reorder must deliver M1 second"


# ═══════════════════════════════════════════════════════════════════════════════
# Primitive 5 — modify
# Assert: recipient receives bytes mutated by mutation_fn, not the original.
# ═══════════════════════════════════════════════════════════════════════════════

def test_modify_mutates_bytes_in_transit(keypair):
    """
    modify(mutation_fn) must apply mutation_fn to the message bytes before
    delivery.  We flip byte 0 of the real M1 wire bytes and verify the received
    bytes differ from the original and that byte 0 has been flipped.
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    sim, attacker = _make_sim()

    m1_bytes = serialize_message(bob.create_m1())

    def flip_first_byte(data: bytes) -> bytes:
        ba = bytearray(data)
        ba[0] ^= 0xFF
        return bytes(ba)

    with attacker.modify(flip_first_byte):
        sim.send("bob", "alice", m1_bytes)

    mutated = sim.receive("alice", timeout=1.0)

    assert mutated != m1_bytes, "modify must produce different bytes"
    assert mutated[0] == (m1_bytes[0] ^ 0xFF), "byte 0 must be flipped"
    assert mutated[1:] == m1_bytes[1:],         "all other bytes must be unchanged"


# ═══════════════════════════════════════════════════════════════════════════════
# Primitive 6 — replay
# Assert: replay delivers a previously captured message to the target again,
#         byte-for-byte identical to the original.
# ═══════════════════════════════════════════════════════════════════════════════

def test_replay_redelivers_captured_bytes(keypair):
    """
    replay(captured_bytes, sid_to, simulator) must inject a previously captured
    byte string into sid_to's queue.

    We capture real M1 wire bytes from a completed handshake via
    attacker.captured, then replay the M1 into a fresh queue and verify
    the byte content is identical.  This is the exact mechanism Stage 7's
    replay attack will use — real captured bytes, not mocks.
    """
    alice, bob, sim, attacker = _run_full_handshake(keypair)

    # Verify we captured 6 real messages
    assert len(attacker.captured) == 6, (
        f"Expected 6 captured messages, got {len(attacker.captured)}"
    )

    # The first captured message is M1 (bob → alice)
    sid_from, sid_to, m1_bytes = attacker.captured[0]
    assert sid_from == "bob"
    assert sid_to   == "alice"

    # Build a fresh sim with its own queue for the replay target
    fresh_sim = NetworkSimulator()
    fresh_sim.register("victim")

    # Replay the captured M1 bytes into the victim's queue
    attacker.replay(m1_bytes, "victim", fresh_sim)

    replayed = fresh_sim.receive("victim", timeout=1.0)
    assert replayed == m1_bytes, (
        "replay must deliver byte-for-byte identical content to the original captured message"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Primitive 6b — intercept (observe-only, no modification)
# Assert: callback is invoked with real bytes; message still arrives unchanged.
# ═══════════════════════════════════════════════════════════════════════════════

def test_intercept_observes_without_modification(keypair):
    """
    intercept(callback) must call callback with real (sid_from, sid_to, bytes)
    for every message in transit, without changing what the recipient receives.
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    sim, attacker = _make_sim()

    m1_bytes = serialize_message(bob.create_m1())

    observed: list = []

    with attacker.intercept(lambda sf, st, b: observed.append((sf, st, b))):
        sim.send("bob", "alice", m1_bytes)

    received = sim.receive("alice", timeout=1.0)

    assert len(observed) == 1,        "intercept callback must be called exactly once"
    assert observed[0][0] == "bob"
    assert observed[0][1] == "alice"
    assert observed[0][2] == m1_bytes, "intercepted bytes must match original"
    assert received        == m1_bytes, "message delivered to recipient must be unchanged"


# ═══════════════════════════════════════════════════════════════════════════════
# Integration — full handshake through simulator, no attacker hooks
# Assert: SESSION ESTABLISHED, keys match, 6 real messages captured.
# ═══════════════════════════════════════════════════════════════════════════════

def test_full_handshake_through_simulator(keypair):
    """
    A complete M1-M6 handshake routed through the NetworkSimulator (zero attacker
    hooks) must produce ESTABLISHED state and identical SessionKeys.

    This is the Stage 6 equivalent of Stage 4's test_full_handshake_session_keys_match,
    but now all messages transit as real wire bytes through the simulator queue.
    """
    alice, bob, sim, attacker = _run_full_handshake(keypair)

    assert alice.session_state == SessionState.ESTABLISHED
    assert bob.session_state   == SessionState.ESTABLISHED
    assert alice.session_key == bob.session_key
    assert len(alice.session_key) == 32

    # Exactly 6 messages must have crossed the network layer
    assert len(attacker.captured) == 6, (
        f"Expected 6 wire messages for M1-M6, got {len(attacker.captured)}"
    )

    # All captured bytes must be non-empty and valid UTF-8 JSON
    import json
    for i, (sf, st, b) in enumerate(attacker.captured):
        assert len(b) > 0, f"message {i} was empty"
        try:
            json.loads(b)
        except json.JSONDecodeError:
            pytest.fail(f"message {i} is not valid JSON: {b[:80]!r}")

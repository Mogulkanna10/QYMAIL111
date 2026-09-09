"""
Attack: Message Replay (Session-ID Reuse).

The attacker captures the real M2 bytes from a completed handshake and
re-injects them into a fresh handshake session.  The server's verify_m2()
checks session_id binding and raises SessionIDMismatch because M2 was
generated for a different session_id.

Defense caught
--------------
backend.protocol.errors.SessionIDMismatch
  → m2.verify_m2: "M2: session_id mismatch"

Paper mapping
-------------
G3 (Replay Resistance) — THREAT_MODEL.md §4
PROTOCOL_SPEC.md §2 M2: session_id is freshly generated per-session in
  create_m1() (os.urandom(16)); it is embedded in CommitC, so any M2
  replayed into a session with a different session_id fails immediately.

How the attack runs
-------------------
1. Run a complete first handshake (session A) with an intercept hook that
   records M2 bytes off the real simulator queue.
2. Start a fresh second handshake (session B) with a *different* session_id
   (guaranteed by a fresh bob.create_m1() call with os.urandom).
3. Hook the simulator so that when session B's Alice would send her M2,
   the attacker replaces it with the captured M2 from session A.
4. Session B's Bob calls verify_m2(replayed_m2, expected_session_id_B)
   → session_id_A ≠ session_id_B → SessionIDMismatch raised.
"""

import threading
from backend.attacks._harness import (
    AttackResult, make_endpoints, run_live_handshake,
    _bob_thread, _alice_thread,
    serialize_message, deserialize_m1, deserialize_m2,
    deserialize_m3, deserialize_m4, deserialize_m5, deserialize_m6,
)
from backend.network.attacker import Attacker
from backend.network.simulator import NetworkSimulator
from backend.protocol.errors import SessionIDMismatch


def run() -> AttackResult:
    """
    Capture a real M2 off a live handshake, replay it into a fresh session.
    Returns AttackResult with blocked=True if SessionIDMismatch is raised.
    """

    # ── Step 1: Run session A, capture M2 bytes ────────────────────────────
    _, alice_a, bob_a, sim_a, attacker_a = make_endpoints()
    captured_m2: list[bytes] = []

    def _capture_m2(sf, st, data, sim):
        # M2 is sent from alice→bob; capture the first such message.
        if sf == "alice" and st == "bob" and not captured_m2:
            captured_m2.append(data)
        return data   # pass through unchanged

    with attacker_a.intercept(lambda sf, st, b: None):
        pass  # intercept context manager used below via hook directly

    # Register a persistent intercept hook for session A
    attacker_a._add_hook(lambda sf, st, data, sim: _capture_m2(sf, st, data, sim))
    errors_a = run_live_handshake(sim_a, attacker_a, alice_a, bob_a)

    assert captured_m2, "Harness error: M2 was not captured from session A"
    real_m2_bytes = captured_m2[0]

    # Confirm session A succeeded (the capture run itself must be clean)
    session_a_errors = [e for _, e in errors_a]
    if session_a_errors:
        return AttackResult(
            attack_name="replay",
            blocked=False,
            failure_reason=f"Harness error: session A failed: {session_a_errors[0]}",
            raw_evidence={"harness_error": str(session_a_errors[0])},
        )

    # ── Step 2: Run session B, inject stale M2 from session A ─────────────
    _, alice_b, bob_b, sim_b, attacker_b = make_endpoints()
    m2_replaced = threading.Event()

    def _inject_stale_m2(sf, st, data, sim):
        """Replace the first alice→bob message (M2) with the captured one."""
        if sf == "alice" and st == "bob" and not m2_replaced.is_set():
            m2_replaced.set()
            return real_m2_bytes   # ← stale M2 from session A
        return data

    attacker_b._add_hook(_inject_stale_m2)
    errors_b = run_live_handshake(sim_b, attacker_b, alice_b, bob_b)

    # ── Step 3: Evaluate result ────────────────────────────────────────────
    bob_errors = [e for role, e in errors_b if role == "bob"]
    session_id_mismatch = next(
        (e for e in bob_errors if isinstance(e, SessionIDMismatch)), None
    )

    if session_id_mismatch:
        return AttackResult(
            attack_name="replay",
            blocked=True,
            failure_reason=(
                f"SessionIDMismatch raised by verify_m2: \"{session_id_mismatch}\""
            ),
            raw_evidence={
                "attack_message": "M2",
                "defense_invariant": "G3 Replay Resistance (THREAT_MODEL.md §4)",
                "protocol_check": "m2.verify_m2: session_id binding",
                "m2_injected_len_bytes": len(real_m2_bytes),
                "m2_replaced_in_session_b": m2_replaced.is_set(),
            },
        )
    else:
        return AttackResult(
            attack_name="replay",
            blocked=False,
            failure_reason="SessionIDMismatch was NOT raised — attack succeeded",
            raw_evidence={
                "bob_errors": [str(e) for e in bob_errors],
                "m2_replaced": m2_replaced.is_set(),
            },
        )

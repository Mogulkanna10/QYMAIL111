"""
Attacker — in-flight message manipulation hooks for Stage 6 / Stage 7.

Each method is a primitive that may be composed to build the five signature
attacks in Stage 7.  Every primitive operates on the real serialized bytes
flowing through the NetworkSimulator queue — no synthetic message objects.

The Attacker is stateful:
  - Capture list records every (sid_from, sid_to, bytes) triple that passes
    through, enabling later replay.
  - A set of enabled hooks is evaluated in order for every outbound message.

Thread-safety: the hook list and capture list are protected by a lock so that
tests running the handshake in two threads can safely configure/read state.

Usage (basic intercept):
    sim = NetworkSimulator()
    attacker = Attacker()
    sim.set_attacker(attacker)

    with attacker.intercept(lambda sf, st, b: print(f"{sf}→{st}: {len(b)}B")):
        sim.send("bob", "alice", some_bytes)

Usage (modify a specific message):
    # Flip byte 0 of every M4 (wrappedC) byte string:
    def flip(b):
        ba = bytearray(b); ba[0] ^= 0xFF; return bytes(ba)

    with attacker.modify_next(flip):
        # The next message that passes through will have byte 0 flipped.
        sim.send("alice", "bob", m4_bytes)
"""

import threading
import time
from contextlib import contextmanager
from typing import Callable, Optional


class Attacker:
    """
    Attacker hook for NetworkSimulator.

    process(sid_from, sid_to, message_bytes, simulator) is called by
    NetworkSimulator.send() before the message is enqueued.  Returns
    modified bytes, or None to drop the message.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._captured: list[tuple[str, str, bytes]] = []
        self._hooks: list[Callable] = []          # applied in order each message

    # ── Internal process hook ─────────────────────────────────────────────

    def process(
        self,
        sid_from: str,
        sid_to: str,
        message_bytes: bytes,
        simulator,
    ) -> Optional[bytes]:
        """
        Called by NetworkSimulator for every outbound message.

        Applies each registered one-shot hook in FIFO order.
        A hook returns (bytes | None) — None means drop.
        """
        with self._lock:
            hooks = list(self._hooks)    # snapshot

        # Record the capture *before* any hook modifies / drops
        with self._lock:
            self._captured.append((sid_from, sid_to, message_bytes))

        current = message_bytes
        for hook in hooks:
            result = hook(sid_from, sid_to, current, simulator)
            # Hook returns (bytes | None | <unchanged sentinel>)
            if result is _UNCHANGED:
                continue
            current = result
            if current is None:
                return None   # dropped

        return current

    def _add_hook(self, hook: Callable):
        with self._lock:
            self._hooks.append(hook)

    def _remove_hook(self, hook: Callable):
        with self._lock:
            try:
                self._hooks.remove(hook)
            except ValueError:
                pass

    # ── Capture & Replay ─────────────────────────────────────────────────

    @property
    def captured(self) -> list:
        """All (sid_from, sid_to, bytes) messages captured since last reset."""
        with self._lock:
            return list(self._captured)

    def reset_captures(self):
        with self._lock:
            self._captured.clear()

    def replay(self, captured_bytes: bytes, sid_to: str, simulator) -> None:
        """
        Re-inject a previously captured byte string into sid_to's queue.

        Uses simulator.enqueue() (direct bypass) so that replaying does
        not trigger another attacker pass — the goal is to deliver the
        unmodified original bytes again, not to layer attacks.
        """
        simulator.enqueue(sid_to, captured_bytes)

    # ── Primitive: delay ─────────────────────────────────────────────────

    @contextmanager
    def delay(self, ms: float):
        """
        Context manager: every message that passes through is delayed by
        `ms` milliseconds before being delivered.
        """
        def _hook(sf, st, data, sim):
            time.sleep(ms / 1000.0)
            return _UNCHANGED

        self._add_hook(_hook)
        try:
            yield
        finally:
            self._remove_hook(_hook)

    # ── Primitive: drop ──────────────────────────────────────────────────

    @contextmanager
    def drop(self):
        """
        Context manager: drop (silently discard) every message that passes
        through while this context is active.
        """
        def _hook(sf, st, data, sim):
            return None   # None → simulator drops the message

        self._add_hook(_hook)
        try:
            yield
        finally:
            self._remove_hook(_hook)

    def drop_next(self, n: int = 1):
        """
        Drop the next `n` messages that pass through (one-shot counter).
        Returns a threading.Event that is set once all n messages are dropped.
        """
        counter = {"remaining": n}
        done = threading.Event()

        def _hook(sf, st, data, sim):
            with self._lock:
                if counter["remaining"] > 0:
                    counter["remaining"] -= 1
                    if counter["remaining"] == 0:
                        done.set()
                    return None
            return _UNCHANGED

        self._add_hook(_hook)
        done._cleanup = lambda: self._remove_hook(_hook)
        return done

    # ── Primitive: duplicate ─────────────────────────────────────────────

    @contextmanager
    def duplicate(self, extra_copies: int = 1):
        """
        Context manager: deliver each message `extra_copies` additional
        times by calling simulator.enqueue() for the extra copies *after*
        the normal delivery path completes.
        """
        def _hook(sf, st, data, sim):
            # Schedule extra copies via direct enqueue (bypasses attacker pass)
            for _ in range(extra_copies):
                sim.enqueue(st, data)
            return _UNCHANGED

        self._add_hook(_hook)
        try:
            yield
        finally:
            self._remove_hook(_hook)

    # ── Primitive: reorder ───────────────────────────────────────────────

    def reorder(self, messages: list[bytes], sid_to: str, simulator) -> None:
        """
        Inject a *reordered* list of already-captured messages into sid_to's
        queue in the given order.  The caller is responsible for supplying the
        messages in the desired (non-chronological) order.

        `messages` must be a list of raw bytes, as returned by self.captured.
        """
        for msg_bytes in messages:
            simulator.enqueue(sid_to, msg_bytes)

    # ── Primitive: modify ────────────────────────────────────────────────

    @contextmanager
    def modify(self, mutation_fn: Callable[[bytes], bytes]):
        """
        Context manager: apply mutation_fn to every message's bytes before
        delivery.  mutation_fn(message_bytes: bytes) -> bytes.

        Example — flip bit 0 of every message:
            with attacker.modify(lambda b: bytes([b[0]^0xFF])+b[1:]):
                sim.send(...)
        """
        def _hook(sf, st, data, sim):
            return mutation_fn(data)

        self._add_hook(_hook)
        try:
            yield
        finally:
            self._remove_hook(_hook)

    # ── Primitive: intercept (observe only) ──────────────────────────────

    @contextmanager
    def intercept(self, callback: Callable[[str, str, bytes], None]):
        """
        Context manager: call callback(sid_from, sid_to, message_bytes) for
        every message in transit, without modifying it.

        Useful for logging, assertion-checking, and capturing specific messages.
        """
        def _hook(sf, st, data, sim):
            callback(sf, st, data)
            return _UNCHANGED

        self._add_hook(_hook)
        try:
            yield
        finally:
            self._remove_hook(_hook)


# ── Sentinel ──────────────────────────────────────────────────────────────────

class _UnchangedType:
    """Sentinel returned by a hook to indicate "pass through unchanged"."""
    __slots__ = ()


_UNCHANGED = _UnchangedType()

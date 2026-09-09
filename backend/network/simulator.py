"""
NetworkSimulator — in-process message queue.

Architecture
------------
Each registered endpoint (identified by a string sid) owns a private
FIFO queue.  send() places bytes into the recipient's queue; receive()
blocks until a message arrives or the timeout expires.

If an Attacker is attached (via set_attacker()), every outbound message
passes through the attacker's process() hook before it reaches the queue.
The attacker may:
  - return the bytes unchanged (pass-through)
  - return modified bytes (tampering)
  - return None (drop)
  - call simulator.enqueue() multiple times (duplicate / replay)
  - insert artificial delays (blocking in the process() call)
  - reorder pending messages already in a queue

Thread-safety
-------------
Each per-endpoint queue is a stdlib queue.Queue (thread-safe).  The
registry lock only protects registration; after registration, queues are
accessed locklessly through their own thread-safe interface.

Usage
-----
    sim = NetworkSimulator()
    sim.register("alice")
    sim.register("bob")

    # pass bytes through (no attacker)
    sim.send("bob", "alice", some_bytes)
    data = sim.receive("alice", timeout=5.0)
"""

import queue
import threading
import time


class NetworkSimulator:
    """
    In-process network simulator for QYMail-TEF Stage 6.

    All message data is raw bytes (the canonical JSON wire encoding
    from backend.network.wire.serialize_message).
    """

    def __init__(self):
        self._queues: dict[str, queue.Queue] = {}
        self._lock = threading.Lock()
        self._attacker = None

    # ── Registration ──────────────────────────────────────────────────────

    def register(self, sid: str) -> None:
        """Register an endpoint.  Must be called before send/receive."""
        with self._lock:
            if sid not in self._queues:
                self._queues[sid] = queue.Queue()

    def registered_sids(self) -> list:
        with self._lock:
            return list(self._queues.keys())

    # ── Attacker ──────────────────────────────────────────────────────────

    def set_attacker(self, attacker) -> None:
        """Attach an Attacker instance.  Pass None to remove."""
        self._attacker = attacker

    # ── Core transport ────────────────────────────────────────────────────

    def enqueue(self, sid_to: str, message_bytes: bytes) -> None:
        """
        Place bytes directly into sid_to's queue, bypassing attacker hooks.
        Used by Attacker.duplicate() and Attacker.replay() to re-inject
        without triggering another attacker pass.
        """
        self._queues[sid_to].put(message_bytes)

    def send(self, sid_from: str, sid_to: str, message_bytes: bytes) -> None:
        """
        Send serialized message bytes from sid_from to sid_to.

        If an attacker is active:
          - attacker.process() is called with (sid_from, sid_to,
            message_bytes, self).
          - The attacker returns either modified bytes or None (drop).
          - If None, the message is silently discarded (attacker dropped it).
        """
        if self._attacker is not None:
            message_bytes = self._attacker.process(
                sid_from, sid_to, message_bytes, self
            )
            if message_bytes is None:
                return  # message dropped by attacker

        self._queues[sid_to].put(message_bytes)

    def receive(self, sid: str, timeout: float = 10.0) -> bytes:
        """
        Block until a message arrives for sid or timeout expires.

        Raises:
            TimeoutError: if no message arrives within the timeout.
        """
        try:
            return self._queues[sid].get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError(
                f"NetworkSimulator.receive: no message for '{sid}' within {timeout}s"
            )

    def peek_queue_size(self, sid: str) -> int:
        """Return the number of messages currently queued for sid (approximate)."""
        return self._queues[sid].qsize()

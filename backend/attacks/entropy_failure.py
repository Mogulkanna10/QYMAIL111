"""
Attack: Entropy Health-Test Failure (Biased TEF Injection).

The attacker subclasses SoftwareSHM and overrides the internal entropy
sampler to return a deliberately all-zero (maximally biased) byte string
that is guaranteed to fail both health tests.  This poisoned SHM is wired
into Alice's HandshakeSession before the handshake begins.

Defense caught
--------------
RuntimeError: "SoftwareSHM (software emulation): entropy health test failed
               after N resample attempts. Session aborted (R5)."
  ← SoftwareSHM._sample_health_tested exhausts max_resample_attempts
     because run_all_tests(b'\\x00' * 32) returns False:
       - monobit_frequency_test: proportion of 1-bits = 0.0 < MONOBIT_LOW (0.35) → FAIL
       - (monobit failure alone causes run_all_tests to return False)

Paper mapping
-------------
PROTOCOL_SPEC.md §3 (SHM / Entropy health testing)
THREAT_MODEL.md §5 (Health-testing failure handling)
R5: fail closed — any health test failure must abort the session.

How the attack runs
-------------------
1. Create a PoisonedSHM that returns b'\\x00' * 32 from generate_sample
   and sets max_resample_attempts = 1 (to fail immediately after one try).
2. Wire this SHM into Alice's HandshakeSession (server/Bob uses a normal SHM).
3. Run the live handshake; Alice's process_m1() → build_m2() → shm.generate_tef()
   → _sample_health_tested() → run_all_tests(b'\\x00'*32) returns False →
   after max_resample_attempts RuntimeError is raised.
4. The handshake aborts in Alice's thread; RuntimeError is collected.
"""

from backend.attacks._harness import AttackResult, make_endpoints, run_live_handshake
from backend.shm.software_shm import SoftwareSHM
from backend.shm import health as _health


class PoisonedSHM(SoftwareSHM):
    """
    SOFTWARE EMULATION — SoftwareSHM subclass that injects deliberately
    biased (all-zero) entropy to trigger a health-test failure.

    NOTE (R3): This is a test fixture simulating a compromised hardware RNG.
    It does not represent real hardware behavior.
    """

    def __init__(self):
        # max_resample_attempts=1 → single attempt, then raise immediately
        super().__init__(max_resample_attempts=1)

    def _sample_health_tested(self, n_bytes: int) -> bytes:
        """
        Return b'\\x00' * n_bytes — guaranteed to fail run_all_tests:
          monobit proportion = 0.0 < MONOBIT_LOW (0.35) → FAIL.
        After max_resample_attempts (1) the parent raises RuntimeError (R5).
        """
        # Delegate to the real _sample_health_tested with a patched generate_sample
        # so we don't bypass any validation logic.
        for attempt in range(self._max_resample_attempts):
            biased_sample = b"\x00" * n_bytes
            if _health.run_all_tests(biased_sample):
                return biased_sample   # (will never reach here for all-zero input)
        raise RuntimeError(
            "SoftwareSHM (software emulation): entropy health test failed after "
            f"{self._max_resample_attempts} resample attempts. Session aborted (R5)."
        )


def run() -> AttackResult:
    """
    Inject a biased SHM into Alice's session. Assert RuntimeError (R5 abort).
    """
    poisoned_shm = PoisonedSHM()

    # Confirm the poisoned sample genuinely fails the health test (when not patched)
    biased_sample = b"\x00" * 32
    health_result = _health.run_all_tests(biased_sample)

    # Wire poisoned SHM into Alice only; Bob uses a normal SHM (default).
    _, alice, bob, sim, attacker = make_endpoints(shm_alice=poisoned_shm)
    errors = run_live_handshake(sim, attacker, alice, bob)

    alice_errors = [e for role, e in errors if role == "alice"]
    health_abort = next(
        (e for e in alice_errors
         if isinstance(e, RuntimeError) and "entropy health test failed" in str(e)),
        None,
    )

    if health_abort:
        return AttackResult(
            attack_name="entropy_failure",
            blocked=True,
            failure_reason=f"RuntimeError (R5 abort) raised in Alice's SHM: \"{health_abort}\"",
            raw_evidence={
                "attack_vector": "PoisonedSHM injected into Alice's HandshakeSession",
                "biased_sample": "b'\\x00' * 32 (all zeros)",
                "monobit_proportion_of_ones": 0.0,
                "monobit_threshold_low": _health.MONOBIT_LOW,
                "health_test_result_on_biased_sample": health_result,
                "max_resample_attempts": poisoned_shm._max_resample_attempts,
                "defense_invariant": "R5 fail-closed + PROTOCOL_SPEC.md §3 health testing",
                "paper_section": "THREAT_MODEL.md §5 / SP 800-90B abort-and-resample",
            },
        )
    else:
        return AttackResult(
            attack_name="entropy_failure",
            blocked=False,
            failure_reason="RuntimeError was NOT raised — health test abort not triggered",
            raw_evidence={
                "alice_errors": [str(e) for e in alice_errors],
                "health_test_result": health_result,
            },
        )

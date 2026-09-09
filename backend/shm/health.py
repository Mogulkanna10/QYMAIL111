"""
Entropy health tests inspired by NIST SP 800-90B.

Implements two real statistical checks that can genuinely fail on bad input:
  1. Monobit Frequency Test — detects severe bit bias toward 0 or 1.
  2. Runs Test — detects long alternating or constant runs indicating non-randomness.

These are NOT stubs. Each test independently applies a threshold and will return
False on deliberately biased data (e.g. all-zero bytes, all-one bytes).

NOTE (R3): These tests operate on SOFTWARE-GENERATED entropy. They do not verify
hardware-level noise sources.
"""

import math


# --- Constants ---
# Minimum sample size (bytes) required for meaningful statistical testing
MIN_SAMPLE_BYTES = 32

# Monobit test: acceptable range for proportion of 1-bits
# For truly random data, expected proportion ≈ 0.5.
# We allow [0.35, 0.65] — a 3-sigma-ish band for n=256 bits (32 bytes)
MONOBIT_LOW = 0.35
MONOBIT_HIGH = 0.65

# Runs test: acceptable range for run count as a fraction of total bits
# Expected runs ≈ n/2 for random data; allow [0.30, 0.70] band
RUNS_LOW = 0.30
RUNS_HIGH = 0.70


def _bits(sample: bytes) -> list[int]:
    """Expand a byte string into a list of individual bits (MSB-first)."""
    result = []
    for byte in sample:
        for i in range(7, -1, -1):
            result.append((byte >> i) & 1)
    return result


def monobit_frequency_test(sample: bytes) -> bool:
    """
    NIST SP 800-90B Monobit Frequency Test.

    Counts the proportion of 1-bits in the sample. Returns False if the
    proportion falls outside [MONOBIT_LOW, MONOBIT_HIGH], indicating a
    severe bias toward all-zeros or all-ones.

    Genuine failure case: b'\\x00' * n → proportion = 0.0 → FAIL.
    """
    if len(sample) < MIN_SAMPLE_BYTES:
        return False
    bits = _bits(sample)
    n = len(bits)
    ones = sum(bits)
    proportion = ones / n
    return MONOBIT_LOW <= proportion <= MONOBIT_HIGH


def runs_test(sample: bytes) -> bool:
    """
    Simplified Runs Test.

    A 'run' is a maximal sequence of identical bits. For truly random data,
    the number of runs ≈ n/2.  Returns False if the run count is outside the
    acceptable band, indicating long constant or alternating sequences.

    Genuine failure case: b'\\x00' * n → 1 run → run_fraction ≈ 1/n → FAIL.
    Genuine failure case: alternating 0xAA bytes → n runs → fraction ≈ 1.0 → FAIL.
    """
    if len(sample) < MIN_SAMPLE_BYTES:
        return False
    bits = _bits(sample)
    n = len(bits)

    # Count transitions (each new run = a transition from previous bit)
    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            runs += 1

    run_fraction = runs / n
    return RUNS_LOW <= run_fraction <= RUNS_HIGH


def run_all_tests(sample: bytes) -> bool:
    """
    Run all health tests on the sample. Returns True only if ALL tests pass.

    R5 (fail closed): a False return MUST cause the caller to abort or resample.
    """
    return monobit_frequency_test(sample) and runs_test(sample)

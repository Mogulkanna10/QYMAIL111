"""
Tests for backend/shm/health.py

These tests verify that health checks can GENUINELY FAIL on bad input and
GENUINELY PASS on good (os.urandom) input — they are not stubs.
"""

import pytest
import os
from backend.shm import health


# --- Monobit Frequency Test ---

def test_monobit_fails_all_zeros():
    """Bad entropy: all-zero bytes have 0% 1-bits — must FAIL monobit test."""
    bad = b"\x00" * 64
    assert health.monobit_frequency_test(bad) is False


def test_monobit_fails_all_ones():
    """Bad entropy: all-0xFF bytes have 100% 1-bits — must FAIL monobit test."""
    bad = b"\xff" * 64
    assert health.monobit_frequency_test(bad) is False


def test_monobit_passes_urandom():
    """Good entropy: os.urandom output must PASS the monobit test (statistically near-certain)."""
    good = os.urandom(64)
    assert health.monobit_frequency_test(good) is True


def test_monobit_too_short_fails():
    """Edge case: sample below minimum size must FAIL."""
    assert health.monobit_frequency_test(b"\x55" * 4) is False


# --- Runs Test ---

def test_runs_fails_all_zeros():
    """Bad entropy: all-zero bytes produce only 1 run — must FAIL the runs test."""
    bad = b"\x00" * 64
    assert health.runs_test(bad) is False


def test_runs_fails_alternating_bits():
    """Bad entropy: 0xAA (10101010) bytes produce maximum alternation — must FAIL."""
    bad = b"\xaa" * 64
    assert health.runs_test(bad) is False


def test_runs_passes_urandom():
    """Good entropy: os.urandom output must PASS the runs test."""
    good = os.urandom(64)
    assert health.runs_test(good) is True


def test_runs_too_short_fails():
    """Edge case: sample below minimum size must FAIL."""
    assert health.runs_test(b"\xab" * 4) is False


# --- Combined run_all_tests ---

def test_run_all_tests_fails_zeros():
    """Combined: all-zero bytes must fail run_all_tests."""
    assert health.run_all_tests(b"\x00" * 64) is False


def test_run_all_tests_passes_urandom():
    """Combined: os.urandom must pass all health tests."""
    assert health.run_all_tests(os.urandom(64)) is True

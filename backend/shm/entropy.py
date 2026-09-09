"""
Raw entropy sample generator.

NOTE (R3): All entropy produced by this module is sourced from os.urandom(),
which is a SOFTWARE EMULATION of hardware TRNG output. This module makes no
claim of hardware-level entropy isolation or hardware-guaranteed randomness.
"""

import os


def generate_sample(length: int) -> bytes:
    """
    Generate a raw entropy sample of the given byte length using os.urandom().

    NOTE (R3): This is SOFTWARE EMULATION of hardware TRNG sampling.
    os.urandom() is seeded by the OS kernel CSPRNG (e.g. /dev/urandom on Linux),
    not a hardware noise source.
    """
    if length <= 0:
        raise ValueError("Sample length must be positive")
    return os.urandom(length)

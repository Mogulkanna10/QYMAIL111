"""
Best-effort zeroization of secret material.

CRITICAL LIMITATION (Global Rule R3):
This module provides BEST-EFFORT, SOFTWARE-LEVEL zeroization only. It does NOT
provide hardware-guaranteed memory clearing. Python's garbage collector, string
immutability, and object lifecycle mean the following are NOT guaranteed:
  - The memory backing a Python `bytes` or `str` object cannot be overwritten
    in place (these types are immutable; the interpreter may hold internal copies).
  - Overwriting a `bytearray` clears THAT object's buffer, but other references
    or interpreter caches may still hold the data.
  - The OS may not immediately reclaim or zero the freed pages.

Best-effort strategy implemented here:
  1. If the stored value is a `bytearray`, overwrite every byte with 0x00.
  2. Delete the reference from the store so Python's reference counter drops to
     zero and the GC becomes eligible to collect it.
  3. Explicitly call `gc.collect()` as a hint (no guarantee).

This is documented per R3 and is the correct behavior for a hackathon prototype
without TPM integration. Do not claim hardware-level zeroization in the UI or pitch.
"""

import gc


def zeroize_bytearray(buf: bytearray) -> None:
    """
    Overwrite a mutable bytearray in place with zero bytes.

    This is the most reliable zeroization achievable in pure Python for
    bytearray-typed secrets.

    NOTE (R3): Does not guarantee OS-level memory clearing. SOFTWARE EMULATION ONLY.
    """
    for i in range(len(buf)):
        buf[i] = 0


def zeroize_store(store: dict, key: str) -> None:
    """
    Best-effort zeroization of a named entry in an in-process secrets store.

    If the stored value is a bytearray, overwrites it byte-by-byte before
    deleting the reference. For immutable bytes objects, only the reference
    is dropped (no in-place zeroing is possible for immutable types in Python).

    Calls gc.collect() as an advisory hint.

    NOTE (R3): BEST-EFFORT SOFTWARE EMULATION. Not hardware-guaranteed.
    No claim is made that the underlying memory is cleared by the OS.
    """
    value = store.get(key)
    if value is not None:
        if isinstance(value, bytearray):
            zeroize_bytearray(value)
        # For immutable bytes, we can only drop the reference
        del store[key]
    gc.collect()

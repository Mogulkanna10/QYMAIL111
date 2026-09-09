# DECISIONS.md

Records implementation decisions where the paper was ambiguous, per Global Rule R7.

---

## D1 — TK (transport key) derivation for MAC1 (Stage 4, m3.py)
**Ambiguity:** The paper uses `TK` in the MAC1 formula but never explicitly defines its derivation outside of stating it proves possession of `ss`.
**Choice:** `TK = HKDF-Expand(HKDF-Extract(salt=b"", ikm=ss), info=b"QYMail-TK-v1", length=32)`. Derived from `ss` only (Fusion not yet available at M3 time). This is also the choice documented in PROTOCOL_SPEC.md §2 M3.
**Status: CLOSED.** Decision implemented in `backend/protocol/m3.py`; verified by test suite. Not a re-opened question.

## D2 — AD for M5 wrappedS (Stage 4, m5.py)
**Ambiguity:** The paper states M4's AD is explicitly TH3 but does not repeat the AD rule for M5's `wrappedS` with the same explicitness.
**Choice:** `AD = TH4` for `wrappedS`, consistent with the transcript-binding design pattern stated throughout Section V.

## D3 — MACS construction (Stage 4, m5.py)
**Ambiguity:** Paper states MACS is a key-confirmation tag but does not specify the exact input format.
**Choice:** `MACS = HMAC(SessionKey, "confirm-S" || TH5)` where `TH5 = SHA3-256(TH4 || canonical({wrappedS}))` — MACS cannot cover itself.

## D4 — TH6 and MACC construction (Stage 4, m6.py)
**Ambiguity:** Paper implies symmetry with MACS but does not fully specify inputs.
**Choice:** `TH6 = SHA3-256(TH5 || canonical(M5_full))` where M5_full includes MACS. `MACC = HMAC(SessionKey, "confirm-C" || TH6)`.

## D5 — PKI / server long-term key trust (Stage 4, session.py)
**Ambiguity:** Paper assumes a trust establishment mechanism for the server's long-term ML-DSA-87 public key but is out-of-scope.
**Choice:** For the prototype, the server's long-term public key is pre-shared/pinned — passed directly to the client `HandshakeSession` constructor. A full PKI is explicitly out of scope (PROTOCOL_SPEC.md §9).

## D6 — max_resample_attempts for SoftwareSHM health test (Stage 3, software_shm.py)
**Ambiguity:** Paper says "abort-and-resample" but does not specify a maximum attempt count.
**Choice:** 5 attempts, consistent with SP 800-90B §4.4 guidance on health-test failure handling.


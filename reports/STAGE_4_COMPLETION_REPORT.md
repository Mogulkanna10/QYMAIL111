# STAGE 4 COMPLETION REPORT — TAKD-PQE Protocol: M1-M6 + State Machine

## 1. Summary
The full TAKD-PQE handshake (M1-M6) was implemented across 11 files in `backend/protocol/`. A strict state machine enforces message ordering — any out-of-sequence action raises `InvalidStateTransition`. The commit-before-reveal ordering (CommitC set in `process_m1`, before `process_m3` is ever called) is structurally enforced by the code path, not by convention. All four HKDF-derived keys use distinct named labels. The CLI handshake completes with matching SessionKeys and both endpoints in ESTABLISHED state. 11 protocol tests pass.

## 2. Deliverables Produced
- [x] `backend/protocol/messages.py` — M1-M6 dataclasses matching PROTOCOL_SPEC.md field-for-field.
- [x] `backend/protocol/state_machine.py` — `SessionState` enum, `InvalidStateTransition`, transition table, `advance()`, `require_state()`.
- [x] `backend/protocol/transcript.py` — `TranscriptManager`: TH0 = SHA3-256("QYMail-init"||sid), THi = SHA3-256(TH(i-1)||canonical(Mi)).
- [x] `backend/protocol/fusion.py` — `compute_fusion(tefc, tefs, session_id)`.
- [x] `backend/protocol/key_schedule.py` — `derive_tk`, `derive_kwrap_c`, `derive_kwrap_s`, `derive_session_key` with all four PROTOCOL_SPEC.md labels.
- [x] `backend/protocol/errors.py` — `ProtocolError` hierarchy: `AttestationError`, `CommitmentError`, `MACError`, `AEADError`, `SessionIDMismatch`.
- [x] `backend/protocol/m1.py` — `build_m1`, `verify_m1`.
- [x] `backend/protocol/m2.py` — `build_m2` (CommitC computed here, before M3), `verify_m2`.
- [x] `backend/protocol/m3.py` — `build_m3` (decaps, derives TK, MAC1), `verify_m3`.
- [x] `backend/protocol/m4.py` — `build_m4`, `verify_m4` (AEAD + commitment binding check).
- [x] `backend/protocol/m5.py` — `build_m5` (wraps TEFS, derives Fusion+SessionKey, TH5, MACS), `verify_m5`.
- [x] `backend/protocol/m6.py` — `build_m6` (TH6, MACC), `verify_m6`.
- [x] `backend/protocol/session.py` — `HandshakeSession` for CLIENT and SERVER roles, orchestrating all of the above.
- [x] `scripts/run_handshake_cli.py` — End-to-end CLI demo.
- [x] `tests/protocol/test_handshake.py` — 11 tests.
- [x] `DECISIONS.md` — Updated with D1-D6.

## 3. Self-Verification Checklist Results
| Check | Command Run | Expected | Actual | Pass/Fail |
|---|---|---|---|---|
| 1. CLI completes M1-M6 + ESTABLISHED | `python scripts/run_handshake_cli.py` | Prints M1 OK...M6 OK, SESSION ESTABLISHED | Exact output produced | PASS |
| 2. SessionKeys byte-identical | Assert in CLI | alice.session_key == bob.session_key | TRUE, printed explicitly | PASS |
| 3. Both endpoints ESTABLISHED | Assert in CLI | Both states == ESTABLISHED | TRUE | PASS |
| 4. Out-of-order M4 before M3 raises | `test_out_of_order_m4_before_m3_raises` | InvalidStateTransition raised | Raised — test passes | PASS |
| 5. pytest tests/protocol | `pytest tests/protocol -v` | All pass, one per message | 11 passed | PASS |
| 6. Commit-before-reveal structural | `test_commit_before_reveal_structural` | CommitC set before process_m3 called | Confirmed — CommitS is None at that point | PASS |

## 4. Raw Test Output

### CLI run
```
liboqs-python faulthandler is disabled
=== QYMail-TEF TAKD-PQE Handshake CLI ===

M1 OK  (server → client: pkS + attestation quote + SigS)
M2 OK  (client → server: KEM ciphertext + CommitC)
M3 OK  (server → client: CommitS + MAC1)
M4 OK  (server → client: wrappedC reveal)
M5 OK  (server → client: wrappedS reveal + MACS)
M6 OK  (client → server: MACC)

=== SESSION ESTABLISHED ===
Alice state : ESTABLISHED
Bob   state : ESTABLISHED

Alice SessionKey[:8]: 9c7ec24943e3dd84...
Bob   SessionKey[:8]: 9c7ec24943e3dd84...

Alice.SessionKey == Bob.SessionKey: TRUE
Both endpoints in state ESTABLISHED: TRUE

All checks passed.
```

### pytest run
```
============================= test session starts ==============================
collected 11 items

tests/protocol/test_handshake.py::test_full_handshake_session_keys_match PASSED [  9%]
tests/protocol/test_handshake.py::test_full_handshake_both_established PASSED [ 18%]
tests/protocol/test_handshake.py::test_m1_invalid_signature_raises PASSED [ 27%]
tests/protocol/test_handshake.py::test_m1_tampered_pks_raises PASSED     [ 36%]
tests/protocol/test_handshake.py::test_m2_wrong_session_id_raises PASSED [ 45%]
tests/protocol/test_handshake.py::test_m3_bad_mac1_raises PASSED         [ 54%]
tests/protocol/test_handshake.py::test_m4_tampered_ciphertext_raises PASSED [ 63%]
tests/protocol/test_handshake.py::test_m5_tampered_macs_raises PASSED    [ 72%]
tests/protocol/test_handshake.py::test_m6_tampered_macc_raises PASSED    [ 81%]
tests/protocol/test_handshake.py::test_out_of_order_m4_before_m3_raises PASSED [ 90%]
tests/protocol/test_handshake.py::test_commit_before_reveal_structural PASSED [100%]

============================== 11 passed in 0.09s ==============================
```

## 5. Hard Gate Criteria — Self-Assessment
| Criterion | Met? (Y/N) | Evidence/Notes |
|---|---|---|
| CLI handshake completes end-to-end with matching SessionKeys | Y | CLI output: `Alice.SessionKey == Bob.SessionKey: TRUE` |
| State machine genuinely rejects out-of-order messages | Y | `test_out_of_order_m4_before_m3_raises` — `InvalidStateTransition` raised when `process_m4` called at state M1_CREATED |
| Commit-before-reveal ordering structurally guaranteed | Y | `CommitC` set in `process_m1()` (m2.py `build_m2`), before any M3 data exists. Confirmed by `test_commit_before_reveal_structural` asserting `_commit_s is None` at that point. |
| Every HKDF-derived key uses a distinct named label | Y | Labels: `QYMail-TK-v1`, `QYMail-KwrapC-v1`, `QYMail-KwrapS-v1`, `QYMail-SessionKey-v1`. Stage 2's `test_labels_produce_distinct_keys` verifies all four produce different outputs. |

## 6. Deviations, Ambiguities, or Assumptions Made
DECISIONS.md entries D1-D5 all logged from this stage. Key item flagged for review: **D1 (TK derivation)** — the paper does not define TK's HKDF derivation explicitly; our choice uses `ss` as IKM with zero salt, consistent with PROTOCOL_SPEC.md §2 M3.

## 7. Known Issues / Not Yet Working
- None.

## 8. Open Questions for Human Review
- D1 (TK derivation): Is `HKDF-Extract(salt=b"", ikm=ss)` → `HKDF-Expand(info=b"QYMail-TK-v1")` the intended construction, or does the paper's authors have a different TK derivation in mind? If the paper has been updated, please share the relevant section.

## STATUS: STAGE 4 COMPLETE — AWAITING HUMAN APPROVAL. DO NOT PROCEED TO STAGE 5.

# QYMail-TEF — Master Staged Build Prompt for Antigravity
### Strict Gated Execution Protocol (14 Stages)

This document is the operating instruction for Antigravity for the entire QYMail-TEF hackathon build. It is designed to be pasted into Antigravity as a persistent project instruction (or split per-stage if your workflow tool has a size limit). Each teammate running their own Antigravity instance should be given **this same document plus the specific stage(s) they own**, so ownership boundaries stay clean even when running in parallel.

---

## PART A — GLOBAL OPERATING RULES (apply to every stage, no exceptions)

Paste this section into `AGENTS.md` at the root of the repository before Stage 0 begins. Antigravity must re-read `AGENTS.md` before starting any stage.

```
You are the lead implementation engineer for QYMail-TEF, a post-quantum, hardware-attested,
dual-entropy-anchored secure email prototype, based on the uploaded IEEE-format research paper
"QYMail-TEF: A Post-Quantum, Hardware-Attested, Dual-Entropy-Anchored Key Agreement Protocol
for Secure Electronic Mail" (TAKD-PQE, M1-M6).

SOURCE OF TRUTH HIERARCHY (in order):
1. The uploaded research paper — for all protocol semantics, security claims, and formulas.
2. PROTOCOL_SPEC.md (produced in Stage 1) — for exact implementation-level message formats.
3. This document (QYMail-TEF_Antigravity_Master_Prompt.md) — for build order and gates.
Never invent, simplify, or "improve" protocol behavior that conflicts with #1 or #2.

NON-NEGOTIABLE RULES:
R1. Never hand-implement cryptographic primitive mathematics (no custom lattice code, no
    custom AES/ChaCha, no custom hash internals). Use liboqs-python for ML-KEM-1024 and
    ML-DSA-87. Use Python's `cryptography` package and `hashlib`/`hmac` stdlib for
    SHA3-256, HKDF-SHA384, HMAC, and ChaCha20-Poly1305.
R2. Preserve exactly, with no shortcuts: M1-M6 message order and content; dual TEFC/TEFS
    commit-before-reveal ordering (commitments in M2/M3, reveals in M4/M5); transcript hash
    chaining THi = SHA3-256(TH(i-1) || Mi); Fusion = SHA3-256(TEFC || TEFS || session_id);
    extract-then-expand HKDF key schedule with distinct per-purpose labels; HMAC key
    confirmation in M3/M5/M6.
R3. SoftwareSHM must be labeled as software emulation everywhere it appears in code comments,
    API responses, and UI strings. Never claim genuine hardware TRNG, hardware attestation,
    or hardware-guaranteed zeroization unless real TPM calls are wired in (Stage 13 stretch
    only), and even then label it "TPM-assisted," never "HSM."
R4. Zero hardcoded results anywhere: no hardcoded benchmark numbers, no hardcoded "attack
    blocked" UI states that aren't driven by a real rejected message, no hardcoded test
    "pass" values. If a number appears in the UI, it must come from a real measurement or
    a real protocol execution in that session.
R5. Fail closed. Any invalid state transition, bad MAC, bad commitment, bad AEAD tag, bad
    signature, or failed entropy health test must abort the session and produce a specific,
    non-secret-leaking error. No silent degradation, no silent fallback to a weaker path.
R6. Never store or log raw secrets: KEM shared secret (ss), TEFC, TEFS, rC, rS, Kwrap,
    SessionKey, any private key material. Logs may reference these by truncated hash or
    "[REDACTED]" only.
R7. If the paper is ambiguous about an implementation detail, do not guess silently. Add a
    one-line entry to DECISIONS.md describing the ambiguity and the simplest safe choice
    made, then proceed. Flag it prominently in the stage completion report.
R8. Every stage has a hard gate (Part B below). You may not begin the next stage's
    implementation work until the current stage's gate has been reported as PASSED by the
    human reviewer. Producing the completion report is not the same as being approved —
    you must wait for explicit human confirmation ("Stage N approved, proceed") before
    writing any code that belongs to Stage N+1.
R9. Never edit or weaken a test to make it pass. If a test fails, fix the implementation,
    not the test. If you believe a test itself is wrong, say so explicitly in the
    completion report instead of silently changing it.
R10. Every stage completion report must be written to a real file at
     `reports/STAGE_<N>_COMPLETION_REPORT.md` using the exact template in Part C, and you
     must state clearly in your final message of that turn: "STAGE <N> COMPLETE —
     AWAITING HUMAN APPROVAL. Do not proceed to Stage <N+1>."
```

---

## PART B — HOW THE GATE WORKS (read this before Stage 0)

For every stage below, you will find three sections:

- **Deliverables** — exact files/functions Antigravity must produce.
- **Self-Verification Checklist** — commands/tests Antigravity must run *itself*, with pass/fail criteria stated explicitly. Antigravity must paste the raw output of these commands into the completion report, not a paraphrase.
- **Hard Gate Criteria** — a list of statements that must ALL be true. If even one is false, the stage is **not** complete, no matter how much code was written. Antigravity must say so honestly in the report rather than mark the stage complete.

The workflow for humans (you and your teammates), every stage:

1. Tell Antigravity: *"Begin Stage N."*
2. Let it work until it produces `reports/STAGE_N_COMPLETION_REPORT.md` and says the halt phrase.
3. Open that report. Paste its full contents to Claude (me) for review.
4. I will tell you PASS / PASS WITH NOTES / FAIL and exactly what to fix if anything.
5. Only after that, tell Antigravity: *"Stage N approved, proceed to Stage N+1"* — or, if there are fixes, *"Stage N needs fixes: [list]. Fix and re-run the Stage N gate before proceeding."*

Do not let Antigravity skip step 3/4. That human-in-the-loop review is the entire point of the gate — it's where I catch protocol drift before it compounds into three more stages of code built on a wrong assumption.

---

## PART C — STAGE COMPLETION REPORT TEMPLATE

Antigravity must produce exactly this structure at the end of every stage (copy this block into the report file and fill it in):

```markdown
# STAGE <N> COMPLETION REPORT — <Stage Title>

## 1. Summary
One paragraph: what was built, in plain language.

## 2. Deliverables Produced
- [ ] file/path/one.py — <one-line purpose>
- [ ] file/path/two.py — <one-line purpose>
(list every file created or modified this stage)

## 3. Self-Verification Checklist Results
| Check | Command Run | Expected | Actual | Pass/Fail |
|---|---|---|---|---|
| ... | ... | ... | ... | ... |

## 4. Raw Test Output
```
(paste full, unedited pytest/CLI output here — not summarized)
```

## 5. Hard Gate Criteria — Self-Assessment
| Criterion | Met? (Y/N) | Evidence/Notes |
|---|---|---|
| ... | ... | ... |

## 6. Deviations, Ambiguities, or Assumptions Made
(reference DECISIONS.md entries, or "None this stage")

## 7. Known Issues / Not Yet Working
(be honest — this is more useful than silence)

## 8. Open Questions for Human Review
(anything you're unsure about)

## STATUS: STAGE <N> COMPLETE — AWAITING HUMAN APPROVAL. DO NOT PROCEED TO STAGE <N+1>.
```

---

## PART D — THE 14 STAGES

---

### STAGE 0 — Environment Verification
**Suggested owner:** whoever sets up first / all three run this individually on their own machine.
**Prerequisite:** none.

**Objective:** Prove the cryptographic toolchain actually works on your Ubuntu machine before any protocol code is written. This is your single highest-risk item — find out now, not on day 5.

**Deliverables:**
- `backend/requirements.txt` pinning exact versions of: liboqs-python, cryptography, fastapi, uvicorn, pydantic, sqlalchemy, pytest, pytest-asyncio, websockets.
- `scripts/verify_environment.py` — a standalone script (no protocol code, just primitive calls) that:
  1. Generates an ML-KEM-1024 keypair, encapsulates, decapsulates, asserts shared secrets match.
  2. Generates an ML-DSA-87 keypair, signs a test message, verifies it, and asserts a tampered message fails verification.
  3. Computes SHA3-256 of a known input and prints the hex digest.
  4. Runs HKDF-SHA384 extract+expand and prints derived key length.
  5. Runs HMAC-SHA384 over a known input.
  6. Runs ChaCha20-Poly1305 encrypt/decrypt round trip and asserts plaintext recovered, and asserts a tampered ciphertext raises an authentication error.
- `VERSIONS.md` recording exact installed versions of Python, liboqs, liboqs-python, OpenSSL, Node, npm, React (as they get pinned).

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | `python scripts/verify_environment.py` exits with code 0 and prints "ALL PRIMITIVES OK" |
| 2 | ML-KEM-1024 shared secrets from both sides are byte-identical |
| 3 | ML-DSA-87 verify() returns True on valid signature, False (not exception-crash) on tampered message |
| 4 | ChaCha20-Poly1305 decrypt of tampered ciphertext raises `InvalidTag` (or equivalent), caught and reported, not crashing the script |
| 5 | `VERSIONS.md` exists and is non-empty |

**Hard Gate Criteria (ALL must be true):**
- verify_environment.py runs with zero errors on a clean `pip install -r requirements.txt`.
- All six primitive checks pass.
- No custom/hand-rolled crypto math appears anywhere in the script.
- VERSIONS.md is complete.

---

### STAGE 1 — Condensed Specification Documents
**Suggested owner:** protocol/crypto person.
**Prerequisite:** Stage 0 approved.

**Objective:** Write the implementation-level spec so that every later stage has an unambiguous reference, without re-deriving the paper's math.

**Deliverables:**
- `PROTOCOL_SPEC.md` (target 3-6 pages): exact wire format of M1-M6 (field names, types, sizes), transcript formula, commitment formula, Fusion formula, HKDF label scheme (list every distinct label used), AEAD associated-data rules, state machine diagram (text form is fine).
- `THREAT_MODEL.md` (1-2 pages): adversary capabilities (Dolev-Yao + eCK-style state leakage, per paper Section IV), trust domains (trusted/partially-trusted/untrusted), out-of-scope items (explicitly copy the paper's out-of-scope list: anonymous routing, SMTP metadata hiding, traffic analysis, post-zeroization RAM scraping).
- `ARCHITECTURE.md` (1-2 pages): the five-layer architecture diagram from the build plan, plus the explicit rule that Alice and Bob are independent processes/instances communicating only through the network simulator.
- `DECISIONS.md` — created empty, ready to receive entries from later stages.

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | Every one of M1-M6's fields listed in PROTOCOL_SPEC.md matches the paper's Section V field lists exactly (cross-check line by line) |
| 2 | THREAT_MODEL.md's trust domain list matches the paper's Section IV three domains exactly |
| 3 | ARCHITECTURE.md explicitly states "Alice and Bob never call each other's functions directly — all messages pass through the network simulator" |
| 4 | No protocol behavior is described in these docs that isn't traceable to a specific paper section (cite section numbers inline) |

**Hard Gate Criteria:**
- All four documents exist, are internally consistent with each other, and are internally consistent with the paper.
- No implementation code has been written yet.

---

### STAGE 2 — Cryptographic Core Module
**Prerequisite:** Stage 1 approved.

**Objective:** Wrap the verified primitives from Stage 0 into clean, tested, reusable functions the protocol layer will call.

**Deliverables:**
- `backend/crypto/kem.py` — `generate_keypair()`, `encapsulate(pk)`, `decapsulate(sk, ct)`.
- `backend/crypto/dsa.py` — `generate_keypair()`, `sign(sk, msg)`, `verify(pk, msg, sig)`.
- `backend/crypto/sha3.py` — `hash256(data: bytes) -> bytes`.
- `backend/crypto/commitment.py` — `commit(tef, r, session_id) -> bytes`, `verify_commitment(commitment, tef, r, session_id) -> bool`.
- `backend/crypto/hkdf.py` — `extract(salt, ikm)`, `expand(prk, info, length)`, with named label constants matching PROTOCOL_SPEC.md exactly.
- `backend/crypto/hmac_util.py` — `compute(key, data)`, `verify(key, data, tag) -> bool`.
- `backend/crypto/aead.py` — `encrypt(key, plaintext, associated_data)`, `decrypt(key, ciphertext, associated_data)` raising a specific exception on auth failure.
- `backend/crypto/serialization.py` — canonical, deterministic serialization for every message type (this is the function referenced by R2 in Part A — two different serializations of the same logical message must never be possible).
- `tests/crypto/test_*.py` — one test file per module above, minimum 3 tests each (happy path, tamper/wrong-input path, edge case).

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | `pytest tests/crypto -v` — all tests pass, zero skipped |
| 2 | `pytest tests/crypto --cov=backend/crypto` shows >80% line coverage |
| 3 | Grep the crypto/ directory for any raw math operations (loops doing modular arithmetic, matrix ops, custom S-boxes) — must return nothing |
| 4 | `commitment.py`'s `verify_commitment` returns False (not exception) for a wrong TEF, wrong nonce, or wrong session_id — test each separately |
| 5 | `serialization.py`: serialize the same logical message object twice, assert byte-identical output both times |

**Hard Gate Criteria:**
- All tests pass, coverage >80% on this module.
- No hand-rolled cryptographic math anywhere (R1 satisfied).
- Every function signature matches what PROTOCOL_SPEC.md implies it needs.

---

### STAGE 3 — SoftwareSHM Layer
**Prerequisite:** Stage 2 approved.

**Objective:** Build the trusted-domain emulation layer, honestly labeled, that the protocol layer will call for entropy, attestation, and zeroization.

**Deliverables:**
- `backend/shm/interface.py` — abstract `SecureHardwareModule` base class with methods matching the build plan (`generate_tef`, `health_test`, `generate_kem_keypair`, `get_attestation_quote`, `sign_attestation`, `secure_store`, `zeroize`).
- `backend/shm/software_shm.py` — concrete implementation using `os.urandom` as the entropy source.
- `backend/shm/entropy.py` — raw sample generator.
- `backend/shm/health.py` — at minimum implement two real statistical checks in the spirit of NIST SP 800-90B (e.g. monobit frequency test and a runs test) that can genuinely fail on bad input, not a stub that always passes.
- `backend/shm/attestation.py` — builds the quote (device_id, firmware_hash, ephemeral_kem_public_key, session_id, timestamp), hashes it (SHA3-256), signs with ML-DSA-87 via `crypto/dsa.py`.
- `backend/shm/zeroization.py` — best-effort overwrite-and-drop-reference implementation, with an explicit docstring stating the Python-level limitation (garbage collector, string immutability) per R3.

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | `pytest tests/shm -v` all pass |
| 2 | Feed `health.py` a deliberately biased/constant byte string (e.g. all zero bytes) and assert the health test correctly FAILS it |
| 3 | Feed `health.py` real `os.urandom` output and assert it PASSES |
| 4 | Attestation quote signature verification succeeds on an unmodified quote and fails on a quote with one byte of the ephemeral public key flipped |
| 5 | Grep every SoftwareSHM-facing string (log messages, docstrings, any UI-bound text produced here) for the word "emulat" or "software" — every hardware-adjacent claim must carry this qualifier |

**Hard Gate Criteria:**
- Health test module can demonstrably fail on bad entropy and pass on good entropy (not a stub).
- No code or string anywhere in this module claims genuine hardware behavior.
- Attestation forgery (tampered ephemeral key, unchanged signature) is caught.

---

### STAGE 4 — TAKD-PQE Protocol: M1-M6 + State Machine
**Prerequisite:** Stage 3 approved. **This is the single most important stage — do not rush it.**

**Objective:** Implement the actual handshake exactly as specified, with a strict state machine that rejects any out-of-order or malformed transition.

**Deliverables:**
- `backend/protocol/messages.py` — dataclasses/pydantic models for M1-M6, matching PROTOCOL_SPEC.md field-for-field.
- `backend/protocol/transcript.py` — `TranscriptManager` implementing TH0 = SHA3-256("QYMail-init" || session_id) and THi = SHA3-256(TH(i-1) || Mi) using `serialization.py` from Stage 2.
- `backend/protocol/fusion.py` — `compute_fusion(tefc, tefs, session_id)`.
- `backend/protocol/key_schedule.py` — HKDF-based derivation of Kwrap,C / Kwrap,S / SessionKey with per-purpose labels, keyed by `ss` and salted by `Fusion` per the paper.
- `backend/protocol/state_machine.py` — explicit state enum (INIT, M1_CREATED, M1_VERIFIED, ..., ESTABLISHED, TEARDOWN, ZEROIZED) and a transition table; any transition not in the table raises `InvalidStateTransition`.
- `backend/protocol/m1.py` through `m6.py` — one module per message: build + verify logic for that message, calling into crypto/, shm/, transcript.py appropriately.
- `backend/protocol/session.py` — `HandshakeSession` tying it all together, orchestrating create→M1..M6→ESTABLISHED, for a single side (client or server role).
- `scripts/run_handshake_cli.py` — CLI script: instantiate alice (client) and bob (server) as separate in-process objects, run the full M1-M6 by directly passing message objects between them (network simulator comes in Stage 6 — for this stage, direct in-process message passing is fine, but keep the call boundary function-based so wiring in the simulator later is a small change, not a rewrite).

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | `python scripts/run_handshake_cli.py` completes and prints `M1 OK, M2 OK, M3 OK, M4 OK, M5 OK, M6 OK, SESSION ESTABLISHED` |
| 2 | Assert alice.SessionKey == bob.SessionKey (byte-identical), printed explicitly in CLI output |
| 3 | Assert alice.session_state == bob.session_state == ESTABLISHED at the end |
| 4 | Attempt to feed M4 before M3 has been processed — assert `InvalidStateTransition` is raised, not a silent pass |
| 5 | `pytest tests/protocol -v` — includes at least one test per message (M1-M6) for both the happy path and one deliberately malformed input |
| 6 | Confirm via code inspection (paste relevant snippet in report) that client entropy commitment (CommitC, in M2) is computed and sent before the client has seen CommitS (in M3) — i.e., verify commit-before-reveal ordering is structurally enforced, not just accidental |

**Hard Gate Criteria:**
- CLI handshake completes end-to-end with matching SessionKeys.
- State machine genuinely rejects out-of-order messages (demonstrated, not asserted).
- Commit-before-reveal ordering is structurally guaranteed by the code path, not just by convention.
- Every HKDF-derived key uses a distinct, named label (list them in the report).

---

### STAGE 5 — Negative & Invariant Testing
**Prerequisite:** Stage 4 approved.

**Objective:** Reproduce the spirit of the paper's 11 invariant checks as real, currently-passing pytest tests, and prove each one can actually fail when it should.

**Deliverables:**
- `tests/protocol/test_invariants.py` covering (at minimum, mirroring the paper Section VI-E list):
  1. Key-agreement equality (already covered Stage 4, re-assert here explicitly)
  2. Commitment binding under tampering (change TEF after commit, assert reveal verification fails)
  3. MAC/tag rejection on transcript modification (flip a byte in a transcript-bound field, assert MAC/AEAD fails)
  4. Replay rejection under session-id reuse
  5. HKDF label separation across derived keys (assert two different-label outputs are different even with same input keying material)
  6. Entropy-fusion bias resistance under a simulated rushing adversary (construct a test where an "attacker" tries to pick TEFS after seeing CommitC only, and assert it has no information to do so — this can be a structural/timing test, document exactly what it proves and doesn't prove)
  7. Volatile-state zeroization occurred (assert the relevant Python object's fields are cleared/overwritten after teardown call)
  8. Wrong session_id rejection
  9. Wrong attestation signature rejection
  10. Out-of-order message rejection (already covered Stage 4, re-assert here)
  11. Tampered AEAD ciphertext rejection

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | `pytest tests/protocol/test_invariants.py -v` — all 11 tests pass |
| 2 | For each of the 11, temporarily comment out the corresponding check in the implementation and confirm the test then FAILS (do this one at a time, then restore) — paste before/after results for at least 3 of them in the report as evidence the tests are real, not tautological |
| 3 | No test achieves a "pass" by catching a broad `Exception` — each must assert the *specific* expected exception type or return value |

**Hard Gate Criteria:**
- All 11 invariant tests pass against the real implementation.
- At least 3 were demonstrated to genuinely fail when the corresponding protection is disabled (proving the tests have teeth).
- Report explicitly maps each of the 11 tests to the paper's corresponding claim/section.

---

### STAGE 6 — Network Simulator
**Prerequisite:** Stage 5 approved.

**Objective:** Route the Stage 4 handshake through a real, separate network layer so that Stage 7's attacks operate on genuine in-flight messages, not function calls.

**Deliverables:**
- `backend/network/simulator.py` — an in-process async message queue with `send(sid_from, sid_to, message_bytes)`, `receive(sid, timeout)`. Alice and Bob must be refactored to send/receive only through this, never direct calls.
- `backend/network/attacker.py` — hooks: `delay(ms)`, `drop()`, `duplicate()`, `reorder(messages)`, `modify(message_bytes, mutation_fn)`, `replay(captured_message)`, `intercept(callback)`. Each operates on the actual serialized bytes in transit.
- Refactor `scripts/run_handshake_cli.py` to route through the simulator with zero attacker hooks active, and confirm it still produces an identical result to Stage 4.

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | `python scripts/run_handshake_cli.py` (now routed through simulator) still produces `SESSION ESTABLISHED` with matching SessionKeys |
| 2 | Code inspection: confirm alice.py/bob.py (or session.py) contain zero direct function calls to each other — only calls to `simulator.send`/`simulator.receive` |
| 3 | `pytest tests/network -v` — tests for delay, drop, duplicate, reorder, modify, replay each individually, confirming the simulator actually alters delivery as instructed |

**Hard Gate Criteria:**
- Handshake success is unchanged with the simulator active and no attacks triggered.
- Direct alice↔bob function calls are structurally impossible (verified by code inspection, quoted in report).
- All six attacker primitives independently demonstrated working on real message bytes.

---

### STAGE 7 — Attack Engine
**Prerequisite:** Stage 6 approved.

**Objective:** Build the five signature attack demonstrations, each grabbing a real in-flight message and mutating it, with the protocol layer's Stage 4/5 protections doing the actual rejecting.

**Deliverables:**
- `backend/attacks/replay.py` — capture M2, let handshake complete or abort naturally, then re-inject the captured M2 into a fresh session; assert rejection.
- `backend/attacks/modification.py` — flip bytes in M4's ciphertext/commitment fields in flight; assert rejection with the specific failure reason surfaced.
- `backend/attacks/rushing.py` — attempt to have a simulated "attacker server" choose TEFS only after observing CommitC (not TEFC itself, which is never on the wire) and demonstrate it has no exploitable information advantage; assert the resulting Fusion is not attacker-influenced.
- `backend/attacks/forged_attestation.py` — modify the ephemeral KEM public key in M1 without modifying SigS; assert ML-DSA-87 verification fails and the client rejects the session.
- `backend/attacks/entropy_failure.py` — inject a deliberately biased sample into the health-test path (reusing Stage 3's health.py) and assert session abort + resample trigger.
- Each attack module exposes a single `run() -> AttackResult` with fields: `attack_name`, `blocked: bool`, `failure_reason: str`, `raw_evidence: dict` (safe-to-display data only, no secrets).

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | `pytest tests/attacks -v` — one test per attack, asserting `blocked == True` and a specific, correct `failure_reason` |
| 2 | For each attack, confirm in the report that the mutated message is the actual serialized bytes captured off the Stage 6 simulator queue, not a synthetic/mocked message object |
| 3 | Run each attack against a version of the code with the relevant Stage 4/5 protection intentionally disabled, and confirm the attack then SUCCEEDS (i.e., `blocked == False`) — this proves the attack is real and the defense is doing the work, not the test being tautological. Restore protection after. |

**Hard Gate Criteria:**
- All five attacks are demonstrated to be blocked against the intact protocol, and to succeed against an intentionally-weakened version (proving causality, not coincidence).
- `failure_reason` strings are specific and technically accurate (e.g. "AEAD authentication tag verification failed" not "error").
- No attack module contains a hardcoded `blocked = True`.

---

### STAGE 8 — Mail Pipeline & Envelope
**Prerequisite:** Stage 7 approved.

**Objective:** Wrap the working, attack-tested protocol in an email-shaped pipeline so a user experiences "compose → send → inbox," not raw protocol calls.

**Deliverables:**
- `backend/mail/envelope.py` — `QYMailEnvelope` dataclass: version, message_id, session_id, sender, recipient, timestamp, nonce, ciphertext, authentication_tag, transcript_hash, protocol_version, security_metadata. Assert via test that no raw secret field can be constructed into this object (e.g. a type-level guard or explicit test that SessionKey/TEFC/TEFS never appear in `envelope.to_dict()`).
- `backend/mail/service.py` — `MailService.send(sender, recipient, subject, body)`: checks for existing valid session → reuses or triggers Stage 4-6 handshake → encrypts with SessionKey via `crypto/aead.py` → builds envelope → sends via `network/simulator.py`.
- `backend/mail/mailbox.py` — SQLite-backed inbox/sent storage, **metadata and ciphertext only**, never plaintext secrets.
- `backend/storage/models.py` / `database.py` — schema for mailbox + session metadata (no raw secrets columns).
- `scripts/run_email_roundtrip_cli.py` — CLI: Alice sends "Hello Bob" to Bob, script prints the full pipeline trace and asserts Bob's inbox contains the correctly decrypted plaintext.

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | `python scripts/run_email_roundtrip_cli.py` — Bob's inbox contains exactly "Hello Bob" (or whatever test string was sent), decrypted correctly |
| 2 | `pytest tests/mail -v` all pass |
| 3 | Query the SQLite database directly after a send and grep for the plaintext SessionKey/TEFC/TEFS hex — must return zero matches |
| 4 | Attempt to send a second email between the same two parties and confirm session reuse occurs (no redundant M1-M6) if within session validity, OR confirm the report explicitly states session caching is deferred and every send re-handshakes (either is acceptable, but it must be stated, not silently ambiguous) |

**Hard Gate Criteria:**
- Full compose→send→decrypt→inbox round trip works via CLI with zero manual key handling.
- Database contains no raw secret material, verified by direct query, not assumption.
- QYMailEnvelope structurally cannot carry raw secrets (R6 satisfied at the type level, not just by convention).

---

### STAGE 9 — Backend API + WebSocket Event Stream
**Prerequisite:** Stage 8 approved.

**Objective:** Expose everything built so far over HTTP/WebSocket so the frontend (Stage 10+) has something real to connect to.

**Deliverables:**
- `backend/main.py` — FastAPI app entrypoint.
- `backend/api/sessions.py` — endpoints to trigger/inspect handshakes.
- `backend/api/mail.py` — compose/send/inbox endpoints wrapping `mail/service.py`.
- `backend/api/attacks.py` — one endpoint per Stage 7 attack, returning `AttackResult` as JSON.
- `backend/api/websocket.py` — a `/ws/events` endpoint streaming: handshake message events (M1 sent, M1 verified, ... ESTABLISHED), attack events, zeroization events — each as a small JSON payload with **no secret fields**.
- `tests/integration/test_api.py` — hits every endpoint via FastAPI's TestClient.

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | `uvicorn backend.main:app` starts without error |
| 2 | `pytest tests/integration -v` all pass |
| 3 | Manually (or scripted) connect to `/ws/events`, trigger a handshake via the API, and confirm the websocket stream emits M1 through M6 events in the correct order in real time |
| 4 | Grep every websocket/API JSON payload definition for secret field names (ss, TEFC, TEFS, SessionKey, sk) — must return zero matches |
| 5 | Trigger an attack via `/api/attacks/{name}` and confirm the JSON response's `blocked` and `failure_reason` fields match what Stage 7's direct tests produced |

**Hard Gate Criteria:**
- Server starts cleanly, all endpoints respond correctly.
- WebSocket stream delivers real-time, correctly-ordered handshake/attack events.
- Zero secret leakage across any API/WS payload, verified by grep, not assumption.

---

### STAGE 10 — Frontend Core Screens
**Suggested owner:** frontend person, can start UI shell earlier against a mocked contract, but must be wired to the real Stage 9 API/WS before this stage is marked complete.
**Prerequisite:** Stage 9 approved.

**Objective:** Build the normal-looking email UI plus the Security Details and Live Handshake views, wired to the real backend.

**Deliverables:**
- `frontend/src/pages/Inbox.tsx`, `Compose.tsx`, `EmailView.tsx`, `Handshake.tsx`.
- `frontend/src/components/SecurityBadge.tsx`, `HandshakeTimeline.tsx`, `MessageInspector.tsx`.
- `frontend/src/services/api.ts`, `websocket.ts` — real calls to the Stage 9 backend, no mocked data remaining.
- Security Details panel showing real (truncated where appropriate) values for: ML-KEM ciphertext hash, ML-DSA signature validity, TEFC/TEFS commitment hashes, transcript hash chain, HKDF-derived key labels used, AEAD status, HMAC confirmation status.

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | With backend running, compose and send an email through the actual UI (not a script) end to end, and confirm it appears correctly in the recipient's inbox in the UI |
| 2 | Live Handshake view shows M1→M6 populating in real time during a send, sourced from the real websocket stream (not a hardcoded animation) |
| 3 | Security Details panel values change between two different sent emails (proving they're live, not static placeholders) |
| 4 | Grep `frontend/src` for any mocked/hardcoded JSON left over from early scaffolding — must return zero remaining mock data in the shipped screens |

**Hard Gate Criteria:**
- All four core screens function against the real backend, with zero remaining mock data.
- Live Handshake view is demonstrably driven by real websocket events, not animation.

---

### STAGE 11 — Attack Lab UI, Security Goals Dashboard, Benchmark Panel
**Prerequisite:** Stage 10 approved.

**Objective:** Build the three panels that will do the most work in front of judges.

**Deliverables:**
- `frontend/src/pages/AttackLab.tsx` — one button per Stage 7 attack, calling the real `/api/attacks/*` endpoints, displaying the real `blocked`/`failure_reason` result.
- `frontend/src/pages/SecurityGoals.tsx` — G1-G10 from the paper (Table I / Section III), each with an honest status tag: `IMPLEMENTED`, `EMULATED`, or `FORMALLY VERIFIED (paper, ProVerif 2.05)` — with a one-line justification per goal, sourced from a static config file that a reviewer (human or Claude) can audit against the actual codebase.
- `frontend/src/pages/Benchmarks.tsx` — connects to `backend/benchmark/runner.py` (new this stage): measures your own primitive and end-to-end handshake latency (n=100 minimum, more if time allows) on this machine, and displays it next to the paper's published numbers (4.26/65.47/305.04 ms LAN/regional/cross-region; 8,635 B total wire overhead) with a short note on measurement differences.

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | Every Attack Lab button, when clicked with backend running, produces a UI result that matches a fresh run of the corresponding Stage 7 pytest test (same blocked/failure_reason) |
| 2 | For every G1-G10 entry marked `IMPLEMENTED`, point to the specific file/test from a prior stage that proves it (list in report) — any goal that can't be pointed to a real artifact must be relabeled `EMULATED` or removed |
| 3 | Run `backend/benchmark/runner.py` twice and confirm the displayed numbers differ slightly between runs (proving they're real measurements, not cached/hardcoded) |
| 4 | Grep `Benchmarks.tsx` and its data source for any literal numeric constant matching the paper's benchmark numbers being used as "your" measured result — must return zero matches (your numbers and the paper's numbers must come from clearly separate fields) |

**Hard Gate Criteria:**
- Every Attack Lab result is live and matches its Stage 7 test.
- Every "IMPLEMENTED" security goal is traceable to a specific real artifact from an earlier stage; none are aspirational.
- Benchmark panel displays genuinely re-measured numbers, distinct from and clearly labeled against the paper's published numbers.

---

### STAGE 12 — Integration Hardening & Internal Security Audit
**Prerequisite:** Stage 11 approved.

**Objective:** Stress the whole system and do the honesty pass that makes this project stand out.

**Deliverables:**
- Run the full compose→handshake→send→decrypt→inbox pipeline at least 20 times in a loop via script; log and fix any flaky failure.
- `SECURITY_LIMITATIONS.md` — condensed, honest limitations list mirroring the paper's Section IX: software-only SHM, in-process network simulator (not real sockets, note this explicitly since Stage 6 chose to skip real TCP unless done as a stretch goal), single-host benchmarks, best-effort Python zeroization, single-session testing only (no corruption-oracle/replicated model).
- `reports/SECURITY_AUDIT.md` — a self-audit checklist covering: every crypto function reviewed for R1 compliance, every API/WS payload reviewed for R6 compliance (secret leakage), every log statement grepped for secret material, every attack re-verified against the final integrated build (not just the isolated Stage 7 tests), every UI security claim checked against what the code actually does (no claim stronger than the implementation).

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | 20-run loop script completes with 20/20 successful round trips (or documents and fixes the failure cause if not) |
| 2 | Full `pytest` (all directories) passes with zero failures and zero skips |
| 3 | `grep -rI -E "(session_key|SessionKey|TEFC|TEFS|shared_secret| ss )" backend/ --include="*.py" | grep -i "print\|log"` (or equivalent) returns zero matches of secret material being logged |
| 4 | Every attack in Attack Lab re-run against the fully integrated system (via the UI, not the isolated Stage 7 unit test) and still correctly blocked |

**Hard Gate Criteria:**
- 20/20 (or documented, fixed, and re-run) successful full pipeline executions.
- Zero failing/skipped tests across the entire suite.
- Zero secret leakage found in logs across the whole codebase.
- SECURITY_AUDIT.md completed with no unresolved findings (or findings explicitly deferred with reasoning in the report).

---

### STAGE 13 — Demo Package & Final Documentation
**Prerequisite:** Stage 12 approved.

**Objective:** Package everything for the actual judging moment. No new features here — packaging and rehearsal only.

**Deliverables:**
- `README.md` — quickstart (clone, install, run backend, run frontend, open UI), one-paragraph project summary, link to the paper.
- `DEMO_SCRIPT.md` — the exact click-by-click sequence for the 5-minute judge demo (compose → live handshake → inbox → security details → attack lab, each attack → security goals → benchmarks → close).
- A recorded backup demo video (screen capture) of one complete clean run, stored outside the repo or as a link, in case live demo fails.
- (Optional stretch, only if all prior stages passed with time remaining) TPM-assisted entropy experiment per the original build plan §6, clearly isolated in its own module so it can be disabled instantly if it misbehaves before judging.

**Self-Verification Checklist:**
| # | Check |
|---|---|
| 1 | A teammate who did not write the code follows README.md from a clean checkout and gets the full system running without needing to ask the author anything |
| 2 | DEMO_SCRIPT.md is rehearsed live at least 3 times, timed, and stays under 5-6 minutes |
| 3 | Backup video exists and plays correctly |

**Hard Gate Criteria:**
- Clean-checkout setup succeeds for a teammate following only the README.
- Demo rehearsed and timed successfully at least 3 times.
- Backup video exists.

---

## PART E — WHAT TO DO IF A STAGE FAILS ITS OWN GATE

Antigravity must never mark a stage complete if any Hard Gate Criterion is false. Instead:
1. State plainly in the completion report which criteria failed and why.
2. Propose a fix plan (what needs to change) without implementing it yet.
3. Halt and output: `STAGE <N> INCOMPLETE — <M> of <T> gate criteria failed. See Section 5. Awaiting human guidance before continuing this stage.`
4. Wait for the human (after Claude review) to say either "proceed with your fix plan" or give a revised approach.

This is the strict-threshold behavior you asked for — it applies exactly the same whether the stage "mostly" worked or barely started. Partial credit does not unlock the next stage.

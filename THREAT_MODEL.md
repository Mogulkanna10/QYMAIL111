# THREAT_MODEL.md — TAKD-PQE Prototype Threat Model

Derived from the paper's Section IV (Threat Model) and Section VI-A (Security Model / oracle definitions).
This document adds one thing the paper doesn't need but the prototype does: an explicit mapping from each
formal capability/oracle to what the hackathon prototype actually implements or emulates, so nobody
overclaims what a UI attack button proves.

---

## 1. Adversary Model

We adopt a **Dolev-Yao adversary** (full network control: can read, inject, modify, delay, drop, reorder any
message) **augmented with eCK-style state-leakage** capabilities (can adaptively expose long-term keys and
ephemeral session state under defined constraints).

### 1.1 Network-level capabilities (all in scope, all must be demonstrable in the Attack Lab or explicitly
noted as "structurally prevented, not separately demonstrated")

| Capability | In prototype via | Attack Lab module |
|---|---|---|
| Passively record traffic (HNDL) | Network simulator captures all message bytes in transit | Not a "blocked" demo — this is inherent; explain in UI that HNDL resistance comes from ML-KEM-1024 hardness, not from hiding traffic |
| Actively inject/modify/delay/drop/reorder | `network/attacker.py` hooks | `modification.py`, and simulator-level delay/drop/reorder tests |
| Replay a captured message into a new/existing session | Capture + re-inject via simulator | `replay.py` |
| Corrupt intermediate SMTP relays | Out of scope for the in-process simulator (no real SMTP relay exists in the prototype) — state this explicitly, do not claim coverage |
| Adaptively corrupt long-term signing keys (sksig,P) | Not implemented as a live oracle in the hackathon prototype (would require a corruption-oracle test harness beyond scope). Represented indirectly by `forged_attestation.py`, which shows the *consequence* of an attacker not holding a valid long-term key — this demonstrates EUF-CMA-style protection, not full oracle-based corruption testing. State this distinction plainly in the Attack Lab UI copy. |
| Query ephemeral state (OEphemeralReveal) for non-test sessions | Not implemented as a formal oracle. `entropy_failure.py` and the zeroization checks (Stage 5 Invariant #7) are the closest practical analogues — they demonstrate that ephemeral material is unavailable/destroyed at the times the paper's guarantees depend on, but this is not the same as a full eCK oracle-based proof. |
| Query completed session keys (OSessionKeyReveal) for non-test sessions | Same as above — not a formal oracle in the prototype; covered qualitatively by the zeroization demo. |

**Rule for the team:** never let the Attack Lab UI or the pitch imply that clicking a button "proves eCK
security." The eCK-style proof is Theorem 1 in the paper (Section VI-C), verified via the game-hopping
reduction and, separately, in ProVerif (Section VI-D). The prototype's job is to demonstrate the *practical
consequences* of those guarantees against concrete, realistic attacks — not to re-run the formal model.

---

## 2. Trust Domains (paper Section IV, exact)

| Domain | Contents | Prototype status |
|---|---|---|
| **Trusted** | SHM (TRNG sampling, non-extractable long-term keys, attestation signing, zeroization) + transient local RAM during computation | **Emulated in software** via `shm/software_shm.py`. Must be labeled "SoftwareSHM — hardware security module behavior emulated in software" everywhere it's user-visible (Global Rule R3). |
| **Partially trusted** | Enterprise/PKI root and local MUA — trusted only to relay payloads faithfully | The `mail/` layer plays this role; it must not have access to raw session secrets (Global Rule R6), only to ciphertext/envelope metadata. |
| **Untrusted** | Network transport and intermediate SMTP relays/MTAs | `network/simulator.py` and `network/attacker.py` model this domain and are exactly where the Attack Lab operates. |

---

## 3. Compromise Models and Scope (paper Section IV, exact)

- **Long-term signing key compromised strictly after a session completes** → forward secrecy (G5)
  preserves that session's confidentiality. *Prototype note:* not separately demonstrated as a live attack
  (would require simulating a completed session followed by a delayed key-extraction attempt) — acceptable
  to state this as "covered by the paper's Theorem 1 reduction, not independently re-demonstrated in the
  hackathon build" rather than fake a demo for it.
- **Ephemeral state compromised mid-session** → only that session's confidentiality is lost; sibling/future
  sessions stay isolated via fresh KEM ephemeral keys and TEF sampling per session (G6). Fresh-per-session
  key/TEF generation is directly demonstrable: run two sequential handshakes and show all ephemeral values
  differ (worth adding as a small verification step in Stage 4 or Stage 5's tests, even though it's not one
  of the paper's original 11 invariants — log it as an added check in DECISIONS.md if included).

### Explicitly Out of Scope (copy exactly from paper Section IV — do not attempt to cover these)
- Anonymous routing
- SMTP metadata hiding
- Traffic-analysis resistance
- Server-side storage privacy
- Post-zeroization RAM-scraping resistance

If any teammate is tempted to add a feature touching these during the hackathon, the answer is no — it's
explicitly out of scope in the source paper and adding it only invites questions you can't answer well under
time pressure.

---

## 4. The Ten Security Goals (paper Section III) — Mapped to Prototype Evidence

| Goal | Description | Evidence in prototype |
|---|---|---|
| G1 | Confidentiality | AEAD (ChaCha20-Poly1305) on email body + Stage 5 tamper tests |
| G2 | Mutual authentication | ML-DSA-87 attestation (M1) + MAC1/MACS/MACC key confirmation chain |
| G3 | Replay resistance | Session-id freshness + `replay.py` attack demo |
| G4 | Session freshness | Fresh ephemeral KEM keypair + TEFs per session (Stage 4/5) |
| G5 | Forward secrecy | Reduction to ML-KEM-1024 IND-CCA2 (paper Theorem 1) — not independently re-proven in prototype, cite paper |
| G6 | Post-compromise security | Fresh ephemeral state per session (see §3 above) |
| G7 | Bias resistance | Commit-before-reveal structural ordering (PROTOCOL_SPEC.md §2, M2/M3) + `rushing.py` attack demo |
| G8 | Transcript integrity | THi chaining + AEAD associated data (PROTOCOL_SPEC.md §4/§7) + `modification.py` attack demo |
| G9 | State/physical destruction | `shm/zeroization.py`, labeled best-effort per R3 |
| G10 | SMTP/IP infrastructure compatibility | Handshake designed as an auxiliary session alongside standard mail delivery, not literally in-band SMTP (paper's own clarification, Section V) — prototype uses a transport abstraction (`network/`) that could be swapped for a real SMTP-adjacent transport later; do not claim unmodified in-band SMTP transport |

Every goal in the Stage 11 Security Goals dashboard must cite one of the evidence items in this table, or be
downgraded from `IMPLEMENTED` to `EMULATED` or removed.

---

## 5. Prototype-Specific Additions (not in the paper, needed because we're building software, not just
proving a protocol)

- **Health-testing failure handling:** the paper requires continuous SP 800-90B-style entropy health
  testing with abort-and-resample on failure (Section V, "Design rationale"). The prototype must make this
  demonstrably real (Stage 3), not a cosmetic pass-through.
- **Fail-closed logging discipline:** every abort path must produce a specific, non-secret-leaking error
  message, both for genuine security value and because "silent failure" is exactly the kind of thing a
  security-literate judge will probe for.
- **In-process network simulator vs. real sockets:** the prototype's default network layer (Stage 6) is an
  in-process simulator, not real TCP/SMTP. This is a legitimate, disclosed scope choice (see build plan) —
  it is not a threat-model gap as long as it's stated plainly in `SECURITY_LIMITATIONS.md` (Stage 12) and
  not implied to be real network transport in the demo narrative.

---

## 6. One-Sentence Summary for the Pitch

"We assume a fully network-controlling Dolev-Yao attacker augmented with eCK-style state-leakage
capabilities, exactly as the paper's formal model does; the hackathon prototype demonstrates the concrete,
practical consequences of that model's guarantees — replay resistance, tamper detection, bias resistance,
authentication, and physical-state destruction — against real, mutated protocol messages, while the
underlying formal security reduction and mechanized verification are the paper's own contribution, not
re-derived here."

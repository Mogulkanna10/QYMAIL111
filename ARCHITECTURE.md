# ARCHITECTURE.md — QYMail-TEF Prototype System Architecture

This document defines the structural rules the codebase must follow for the rest of the build. It does not
repeat protocol semantics (see `PROTOCOL_SPEC.md`) or adversary assumptions (see `THREAT_MODEL.md`) —
it defines layers, boundaries, and the one rule that makes the Attack Lab honest: **Alice and Bob never call
each other directly.**

---

## 1. Layer Diagram

```
┌──────────────────────────────────────────────────────────┐
│ USER-FACING UI (React + TypeScript)                       │
│                                                            │
│ Inbox | Compose | Email View | Security Details |         │
│ Live Handshake | Attack Lab | Security Goals | Benchmarks │
└────────────────────────────┬───────────────────────────────┘
                              │  HTTP + WebSocket only
┌────────────────────────────▼───────────────────────────────┐
│ MAIL APPLICATION LAYER (backend/mail/, backend/api/)       │
│                                                              │
│ MailService | Envelope | Mailbox (SQLite, metadata only)   │
└────────────────────────────┬───────────────────────────────┘
                              │  function calls only, same process
┌────────────────────────────▼───────────────────────────────┐
│ QYMAIL SECURITY LAYER (backend/protocol/)                  │
│                                                              │
│ SessionManager | ProtocolStateMachine | TranscriptManager   │
│ CommitmentManager | FusionManager | KeySchedule             │
└────────────────────────────┬───────────────────────────────┘
                              │  function calls only, same process
┌────────────────────────────▼───────────────────────────────┐
│ CRYPTOGRAPHIC CORE (backend/crypto/)                        │
│                                                               │
│ kem.py | dsa.py | sha3.py | commitment.py | hkdf.py |       │
│ hmac_util.py | aead.py | serialization.py                   │
└────────────────────────────┬───────────────────────────────┘
                              │  function calls only, same process
┌────────────────────────────▼───────────────────────────────┐
│ SOFTWARE SHM LAYER (backend/shm/)  — EMULATED, labeled as   │
│ such everywhere it surfaces in UI/logs (Global Rule R3)     │
│                                                               │
│ EntropyProvider | HealthTester | AttestationManager |        │
│ ZeroizationManager                                            │
└──────────────────────────────────────────────────────────────┘
```

A separate, structurally independent layer connects the two endpoints:

```
                        UNTRUSTED NETWORK
                  ┌───────────────────────────────┐
                  │                                 │
   Alice Endpoint ─┤   network/simulator.py         ├─ Bob Endpoint
   (full stack     │   network/attacker.py          │  (full stack
    above)         │   delay | drop | reorder |     │   above)
                  │   modify | replay | intercept  │
                  │                                 │
                  └───────────────┬─────────────────┘
                                  │
                              Attacker
                        (Attack Lab drives this)
```

---

## 2. The One Rule That Matters Most: Endpoint Independence

**Alice and Bob must be modeled as two structurally independent instances of the full stack above (each
with its own SessionManager, SoftwareSHM, mailbox, and crypto engine), communicating only through
`network/simulator.py`.**

Why this matters more than it might seem: if Alice's code ever calls a function on Bob's object directly (or
vice versa), then every attack in the Attack Lab becomes theater — a "replay attack" that isn't actually
replaying bytes off a real transport has proven nothing. This single architectural rule is what makes Stage
6/7's attacks honest, and it is checked explicitly in both stages' Hard Gate Criteria (grep for cross-endpoint
direct calls — must return zero).

**Practically:** implement each endpoint as its own Python object/process boundary (a process boundary is
not required for the hackathon timeline — an object boundary with a hard rule of "only talk through
`simulator.send()`/`simulator.receive()`" is sufficient and much faster to build and debug). If time allows
post-Stage-12, upgrading to real separate OS processes over localhost TCP is the natural stretch step (see
build plan §6).

---

## 3. Directory-to-Layer Mapping

| Layer | Directory | Depends on |
|---|---|---|
| UI | `frontend/src/` | Mail Application Layer (via HTTP/WS only) |
| Mail Application | `backend/mail/`, `backend/api/` | QYMail Security Layer |
| QYMail Security | `backend/protocol/` | Crypto Core, Software SHM |
| Crypto Core | `backend/crypto/` | liboqs-python, `cryptography`, stdlib only — no layer above |
| Software SHM | `backend/shm/` | Crypto Core (for signing attestation quotes), OS entropy source |
| Network | `backend/network/` | Crypto Core's `serialization.py` only (for canonical bytes) — must not import from `protocol/` beyond message type definitions, to keep it a genuine transport-layer abstraction |
| Attacks | `backend/attacks/` | `network/` (operates on real in-flight messages) |
| Storage | `backend/storage/` | Nothing above Mail Application Layer may query storage directly except through `mail/mailbox.py` |
| Benchmark | `backend/benchmark/` | Crypto Core + Protocol layer, invoked standalone, not part of the live send path |

**Dependency direction is strictly downward** (UI → Mail → Security → Crypto/SHM). No layer may import
from a layer above it. This is checked at Stage 12's audit via import-graph inspection.

---

## 4. Two-Endpoint Deployment Modes (for reference — only Mode 1 is required for the hackathon)

```
Mode 1 (required, Stage 0-12 target):
  Single process, two in-memory endpoint objects, network/simulator.py as the only bridge.

Mode 2 (stretch, Stage 13 only, if ahead of schedule):
  Two OS processes on one machine (e.g. localhost:8001 / localhost:8002),
  network/tcp_transport.py replacing network/simulator.py underneath the same
  send()/receive() interface — protocol and crypto layers unchanged.

Mode 3 (not planned for this hackathon):
  Two physical laptops on a LAN. Do not attempt unless Mode 2 is solid with time to spare.
```

The `network/` layer's interface (`send`, `receive`, `delay`, `drop`, `reorder`, `modify`, `replay`,
`intercept`) must be identical across all three modes so that swapping the transport implementation never
requires touching `protocol/` or `crypto/` code. This is what makes Mode 2 a safe stretch goal instead of a
rewrite risk.

---

## 5. QYMailEnvelope — the Only Thing That Crosses the Mail/Security Boundary Outward

The Mail Application Layer never sees raw secrets (Global Rule R6). The only object that crosses from the
Security Layer up to the Mail Layer (for storage/transport) is `QYMailEnvelope`:

```
version | message_id | session_id | sender | recipient | timestamp | nonce |
ciphertext | authentication_tag | transcript_hash | protocol_version | security_metadata
```

`security_metadata` may include non-secret, display-safe fields (e.g. which anchors were used, truncated
hashes for the Security Details panel) — never raw key material, TEFs, or the SessionKey itself. This
boundary is enforced by type/test in Stage 8 (`envelope.to_dict()` must be provably secret-free).

---

## 6. What Talks to What, Summarized for Judges (one paragraph you can say out loud)

"Alice and Bob are two independent instances of the same five-layer stack. They never call each other's
code directly — every single message, from the very first handshake message to the encrypted email body,
crosses a network simulator layer that an attacker sits inside of. That's not a cosmetic detail: it's what
makes every attack in our Attack Lab a demonstration against real, in-flight protocol bytes, not a scripted
animation."

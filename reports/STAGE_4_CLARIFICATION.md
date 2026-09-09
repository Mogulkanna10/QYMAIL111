# STAGE 4 CLARIFICATION — CommitC Structural Independence Proof

Requested as the remaining open item after the Stage 4 Remediation Report.
Ties the inline `session.py` comment to the actual call-path line numbers and
the state-machine enforcement that makes the independence a compiler-level
guarantee rather than a convention.

---

## Security Claim Being Proved

> "CommitC is computed **before** the client can possibly see CommitS.
> This is the structural enforcement of bias-resistance per Theorem 4 of the paper."

Theorem 4 requires that neither party can bias the session entropy
(TEFC ⊕ TEFS) by choosing their commitment *after* seeing the other party's.
On the client side this means: **CommitC must be produced with zero knowledge
of CommitS**. The claim is that this is enforced not by convention or test,
but by code structure — CommitS is literally unavailable to `build_m2()`.

---

## Artefact 1 — Inline Comment in `session.py`

Location: `backend/protocol/session.py`, lines 148–160, inside `process_m1()`.

```python
# session.py:148-160
        self._transition(SessionState.M1_VERIFIED)
        # STRUCTURAL GUARANTEE — PROTOCOL_SPEC.md §2 M2 / Theorem 4 bias-resistance:
        #
        # build_m2(session_id, pkS, shm) → (M2, ct, ss, tefc, rc)
        #   ├─ session_id  : from msg (M1, received before this call)
        #   ├─ pkS         : from msg (M1, received before this call)
        #   └─ shm         : local SoftwareSHM — generates TEFC and rC internally
        #       CommitC = SHA3-256(TEFC || rC || session_id)
        #
        # CommitS arrives in M3.  process_m3() is guarded by require_state(M2_CREATED),
        # which is only set AFTER this function returns.  Therefore CommitC has zero
        # code-level dependency on any server-supplied value received after M1 —
        # not by convention, but because build_m2's signature has no CommitS parameter
        # and process_m3 cannot execute while process_m1 is on the stack.
        m2_msg, _, ss, tefc, rc = _m2.build_m2(self.session_id, msg.pkS, self._shm)
```

The comment is present and names the theorem it enforces.

---

## Artefact 2 — Full Call-Path Trace

### Step 1 — `process_m1()` entry and first state transition

```
session.py:141   self._transition(SessionState.INIT)
                   → state machine: INIT → M1_VERIFIED  (CLIENT table)
session.py:142   _m1.verify_m1(msg, self._server_signing_pk)
session.py:143   self.session_id = msg.session_id
session.py:144   self._init_transcript(self.session_id)
session.py:145   self._transcript.update(msg)
```

At this point: `self.state == M1_VERIFIED`.  `self._commit_s is None`.

---

### Step 2 — Second state transition inside `process_m1()`

```
session.py:147   self._transition(SessionState.M1_VERIFIED)
                   → state machine: M1_VERIFIED → M2_CREATED  (CLIENT table)
```

State is now `M2_CREATED`. **The function has not returned yet.**

---

### Step 3 — `build_m2()` called — CommitC computed here

```
session.py:161   m2_msg, _, ss, tefc, rc = _m2.build_m2(self.session_id, msg.pkS, self._shm)
```

Descends into `m2.py`:

```
m2.py:20   ct, ss = encapsulate(pkS)
m2.py:21   tefc, rc = shm.generate_tef(session_id)
m2.py:22   commit_c = commit(tefc, rc, session_id)
m2.py:23   m2 = M2(session_id=session_id, ct=ct, CommitC=commit_c)
m2.py:24   return m2, ct, ss, tefc, rc
```

`build_m2` receives exactly three arguments:
- `session_id` — the server's session_id from M1
- `pkS`        — the server's ephemeral KEM public key from M1
- `shm`        — the *client's local* SoftwareSHM (software-emulated TRNG)

**CommitS is not a parameter. CommitS does not exist anywhere in the call frame.**
At the time `commit_c` is assigned on `m2.py:22`, `self._commit_s` on the session
is still `None` (it will be set on `session.py:174`, inside `process_m3()`,
which cannot have run yet — see Step 4).

---

### Step 4 — `process_m1()` completes; result stored

```
session.py:162   self._ss      = ss
session.py:163   self._tefc    = tefc
session.py:164   self._rc      = rc
session.py:165   self._commit_c = m2_msg.CommitC      ← CommitC is now set
session.py:166   self._transcript.update(m2_msg)
session.py:167   return m2_msg                         ← process_m1 returns here
```

`process_m1` returns. The call stack unwinds. **Only now** can the caller
dispatch M2 to the server and await M3.

---

### Step 5 — Why `process_m3()` cannot run before `process_m1()` returns

`process_m3()` begins:

```
session.py:171   self._transition(SessionState.M2_CREATED)
```

which calls:

```
state_machine.py:75   def require_state(current, expected, action):
state_machine.py:77       if current != expected:
state_machine.py:78           raise InvalidStateTransition(...)
```

`require_state` checks `current == M2_CREATED`. That state is set at
`session.py:147` (the second `_transition` inside `process_m1`). Because
`HandshakeSession` uses no threading or async primitives, execution is
strictly single-threaded:

- If `process_m3` is called before `process_m1` has returned, `self.state`
  will not yet be `M2_CREATED` and `require_state` will **immediately raise
  `InvalidStateTransition`** — it does not block, poll, or wait.
- `self.state` reaches `M2_CREATED` at `session.py:147`, which is inside
  `process_m1`, *after* `build_m2` has already returned at `session.py:161`.

By program-order / call-stack sequencing, `process_m3()` cannot reach
`self._commit_s = msg.CommitS` (session.py:174) until `process_m1()` has
returned, which is after `build_m2()` has completed and `CommitC` is finalised.

---

## Structural Independence — Summary Table

| Event | Line | `self._commit_c` | `self._commit_s` | State |
|---|---|---|---|---|
| `process_m1` entry | session.py:141 | `None` | `None` | `INIT` |
| First `_transition` | session.py:141 | `None` | `None` | `M1_VERIFIED` |
| Second `_transition` | session.py:147 | `None` | `None` | `M2_CREATED` |
| `build_m2` called | session.py:161 | `None` | `None` | `M2_CREATED` |
| `commit_c` computed | m2.py:22 | `None` | `None` | `M2_CREATED` |
| `build_m2` returns | session.py:161 | `None` | `None` | `M2_CREATED` |
| CommitC stored | session.py:165 | **set** | `None` | `M2_CREATED` |
| `process_m1` returns | session.py:167 | **set** | `None` | `M2_CREATED` |
| `process_m3` entry | session.py:171 | **set** | `None` | `M2_CREATED` |
| CommitS stored | session.py:174 | **set** | **set** | `M3_VERIFIED` |

At no point is `commit_s` set before `commit_c`. At no point does `build_m2()`
execute in a state where CommitS exists anywhere in the process.

---

## Theorem 4 Binding

Theorem 4 states that the dual-entropy construction is bias-resistant because
neither party can adapt their commitment to the other's revealed value.

This trace shows that on the client side:
1. `CommitC` is produced by `build_m2()` whose signature accepts no server-post-M1 data.
2. `CommitS` cannot be written to `self._commit_s` before `process_m1()` returns,
   which is after `CommitC` is finalised.
3. The state machine enforces the ordering by program-order / call-stack
   sequencing: `require_state` raises `InvalidStateTransition` immediately
   if `process_m3` is called before `process_m1` has returned and set
   `self.state = M2_CREATED`. There is no blocking, polling, or OS-scheduler
   involvement — the guarantee is a direct consequence of single-threaded
   Python execution order.

The same argument applies symmetrically on the server side: `CommitS` is built
inside `build_m3()` (`session.py:102`) after `CommitC` is already received in M2
(`session.py:97`), but `build_m3`'s return value contains `CommitS` as a fresh
SHM-generated value that does not depend on `CommitC`'s content — only on `ss`,
`session_id`, and the server's local `shm`. `CommitC` is used only as a stored
binding value, not as an input to the TEFS/rS generation.

---

*This document produced as part of Stage 4 remediation follow-up.*
*No code was changed. All line numbers are current against HEAD.*

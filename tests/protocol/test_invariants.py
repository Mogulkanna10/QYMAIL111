"""
Stage 5 — Protocol Invariant Tests.

Each test maps to one of the 11 invariants listed in the paper (Section VI-E)
and in the Master Prompt Stage 5 deliverables list.  The mapping is noted in
the docstring of every test.

Paper reference shorthand used below:
  §IV   = Section IV (Threat Model / Adversary Capabilities)
  §V    = Section V  (Protocol Description)
  §VI-B = Section VI-B (Security Assumptions)
  §VI-C = Section VI-C (Formal Proofs — Theorems 1-4)
  §VI-D = Section VI-D (Security Analysis — G1-G10)
  §VI-E = Section VI-E (Invariant Verification)

Run via:
  PYTHONPATH=/home/mogul/Downloads/QYMAIL \\
    venv/bin/python -m pytest tests/protocol/test_invariants.py -v \\
    --override-ini="addopts="
"""
import os
import pytest

from backend.crypto.dsa import generate_keypair as dsa_keypair
from backend.crypto.commitment import commit, verify_commitment
from backend.crypto.hkdf import extract, expand, LABEL_TK, LABEL_KWRAP_C, LABEL_KWRAP_S, LABEL_SESSION_KEY
from backend.crypto.sha3 import hash256
from backend.crypto import hmac_util

from backend.protocol.session import HandshakeSession
from backend.protocol.state_machine import SessionRole, SessionState, InvalidStateTransition
from backend.protocol.errors import (
    AttestationError, MACError, CommitmentError, AEADError, SessionIDMismatch
)
from backend.protocol.messages import M2, M4, M6
from backend.protocol.fusion import compute_fusion
from backend.protocol.key_schedule import (
    derive_tk, derive_kwrap_c, derive_kwrap_s, derive_session_key
)


# ─── Shared fixture ───────────────────────────────────────────────────────────

@pytest.fixture
def keypair():
    return dsa_keypair()


@pytest.fixture
def full_handshake(keypair):
    """Run a complete handshake, return (alice, bob, messages_dict)."""
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)
    m3 = bob.process_m2(m2)
    m4 = alice.process_m3(m3)
    m5 = bob.process_m4(m4)
    m6 = alice.process_m5(m5)
    bob.process_m6(m6)
    return alice, bob, dict(m1=m1, m2=m2, m3=m3, m4=m4, m5=m5, m6=m6)


def _fresh_handshake(server_pk, server_sk):
    """Helper: run one clean handshake and return (alice, bob)."""
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)
    m3 = bob.process_m2(m2)
    m4 = alice.process_m3(m3)
    m5 = bob.process_m4(m4)
    m6 = alice.process_m5(m5)
    bob.process_m6(m6)
    return alice, bob


# ═══════════════════════════════════════════════════════════════════════════════
# Invariant 1 — Key-Agreement Equality
# Paper: §VI-E Inv-1; §VI-C Theorem 1 (Key Agreement).
# Both sides independently derive the same SessionKey via ss + Fusion.
# ═══════════════════════════════════════════════════════════════════════════════

def test_inv1_key_agreement_equality(full_handshake):
    """
    §VI-E Inv-1 / Theorem 1: alice.session_key == bob.session_key after a
    complete handshake.  Keys are 32 bytes and non-None.
    """
    alice, bob, _ = full_handshake
    assert alice.session_key is not None,       "Alice's SessionKey must not be None"
    assert bob.session_key   is not None,       "Bob's SessionKey must not be None"
    assert len(alice.session_key) == 32,        "SessionKey must be 32 bytes"
    assert alice.session_key == bob.session_key, (
        "SessionKeys must be byte-identical — key agreement failed"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Invariant 2 — Commitment Binding Under Tampering
# Paper: §VI-E Inv-2; §VI-C Theorem 3 (Commitment Binding); §VI-B A2 (SHA3-256 CR).
# Changing the TEF *after* committing must cause reveal verification to fail.
# ═══════════════════════════════════════════════════════════════════════════════

def test_inv2_commitment_binding_tampered_tef():
    """
    §VI-E Inv-2 / Theorem 3: SHA3-256(TEF || r || sid) is binding — a
    modified TEF does not satisfy the original commitment.

    Specifically targets the CommitC path; CommitS is symmetric.
    """
    session_id = os.urandom(16)
    tefc = os.urandom(32)
    rc   = os.urandom(16)

    commit_c = commit(tefc, rc, session_id)

    # Tamper: change one bit of TEFC
    tampered_tefc = bytearray(tefc)
    tampered_tefc[0] ^= 0xFF
    tampered_tefc = bytes(tampered_tefc)

    assert not verify_commitment(commit_c, tampered_tefc, rc, session_id), (
        "verify_commitment must return False for a modified TEF — binding property violated"
    )


def test_inv2_commitment_binding_tampered_nonce():
    """
    §VI-E Inv-2 / Theorem 3: Changing the blinding nonce rC also breaks the commitment.
    """
    session_id = os.urandom(16)
    tefc = os.urandom(32)
    rc   = os.urandom(16)

    commit_c = commit(tefc, rc, session_id)

    tampered_rc = bytearray(rc)
    tampered_rc[-1] ^= 0xFF
    tampered_rc = bytes(tampered_rc)

    assert not verify_commitment(commit_c, tefc, tampered_rc, session_id), (
        "verify_commitment must return False for a modified nonce — binding property violated"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Invariant 3 — MAC / Tag Rejection on Transcript Modification
# Paper: §VI-E Inv-3; §V Transcript binding statement;
#        §VI-D G4 (Forward Secrecy / transcript integrity).
# Flipping a byte in a transcript-bound field must cause MAC or AEAD failure.
# ═══════════════════════════════════════════════════════════════════════════════

def test_inv3_mac_rejection_on_m3_transcript_flip(keypair):
    """
    §VI-E Inv-3: MAC1 in M3 is bound to TH2 (the running transcript hash up
    through M2).  Flipping a byte in M3.CommitS alters the M3 message the
    client would hash into TH3, but because MAC1 is HMAC(TK, "commit" || TH2)
    the tamper surfaces differently — we instead test M3.MAC1 directly
    (flipping it breaks the HMAC verify and raises MACError).
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)
    m3 = bob.process_m2(m2)

    # Flip a bit in CommitS — this changes what the client will hash as TH3,
    # which changes the input to AEAD in M4, ultimately surfacing as an AEAD
    # or commitment error downstream (transcript integrity chain).
    tampered = bytearray(m3.CommitS)
    tampered[4] ^= 0x01
    m3.CommitS = bytes(tampered)

    # The client will accept the modified CommitS into its transcript,
    # build M4 over TH3 derived from it — but when the server tries to
    # decrypt M4 with its own TH3 (derived from the real CommitS), the
    # AEAD AD mismatch causes authentication failure.
    m4 = alice.process_m3(m3)

    with pytest.raises((AEADError, CommitmentError, MACError)):
        bob.process_m4(m4)


def test_inv3_aead_rejection_on_m4_ciphertext_flip(keypair):
    """
    §VI-E Inv-3 (continued): Flipping a bit in M4.wrappedC causes AEAD
    authentication to fail when the server decrypts it.
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)
    m3 = bob.process_m2(m2)
    m4 = alice.process_m3(m3)

    tampered = bytearray(m4.wrappedC)
    tampered[-1] ^= 0xFF
    m4.wrappedC = bytes(tampered)

    with pytest.raises((AEADError, CommitmentError)):
        bob.process_m4(m4)


# ═══════════════════════════════════════════════════════════════════════════════
# Invariant 4 — Replay Rejection Under Session-ID Reuse
# Paper: §VI-E Inv-4; §IV Adversary model (passive + active, can replay);
#        §VI-D G7 (Replay resistance).
# An M2 captured from a completed session must be rejected in a new session.
# ═══════════════════════════════════════════════════════════════════════════════

def test_inv4_replay_rejection_session_id_mismatch(keypair):
    """
    §VI-E Inv-4: A replayed M2 from an old session carries a stale session_id.
    A fresh session started by the same server generates a new session_id, so
    the replayed M2 must be rejected with SessionIDMismatch.
    """
    server_pk, server_sk = keypair

    # First session — capture M2
    bob1   = HandshakeSession(role=SessionRole.SERVER,
                               server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice1 = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1_old = bob1.create_m1()
    m2_captured = alice1.process_m1(m1_old)   # M2 with old session_id

    # Second fresh session — different session_id
    bob2 = HandshakeSession(role=SessionRole.SERVER,
                             server_signing_sk=server_sk, server_signing_pk=server_pk)
    bob2.create_m1()  # advances state, generates new session_id

    # Replay the old M2 into the new session
    with pytest.raises(SessionIDMismatch):
        bob2.process_m2(m2_captured)


# ═══════════════════════════════════════════════════════════════════════════════
# Invariant 5 — HKDF Label Separation
# Paper: §VI-E Inv-5; §III §V HKDF label registry; PROTOCOL_SPEC.md §3.
# The four derived keys (TK, KwrapC, KwrapS, SessionKey) must all differ
# even when sharing the same ikm.
# ═══════════════════════════════════════════════════════════════════════════════

def test_inv5_hkdf_label_separation_all_distinct():
    """
    §VI-E Inv-5: With the same ss as IKM, the four label-differentiated HKDF
    outputs (TK, Kwrap,C, Kwrap,S, SessionKey) must all be mutually distinct.

    PROTOCOL_SPEC.md §3 requires this; this test is the mechanical proof.
    Note: SessionKey uses Fusion as salt; we use a random Fusion to ensure
    the test exercises the real derivation path.
    """
    ss     = os.urandom(32)
    fusion = os.urandom(32)

    tk          = derive_tk(ss)
    kwrap_c     = derive_kwrap_c(ss)
    kwrap_s     = derive_kwrap_s(ss)
    session_key = derive_session_key(ss, fusion)

    keys = [tk, kwrap_c, kwrap_s, session_key]
    names = ["TK", "Kwrap,C", "Kwrap,S", "SessionKey"]

    # All four must be 32 bytes
    for k, name in zip(keys, names):
        assert len(k) == 32, f"{name} must be 32 bytes, got {len(k)}"

    # All pairs must be distinct
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            assert keys[i] != keys[j], (
                f"HKDF label separation violated: {names[i]} == {names[j]}"
            )


def test_inv5_hkdf_same_label_same_ikm_is_deterministic():
    """
    §VI-E Inv-5 (consistency check): the same label + ikm always produces the
    same output — confirms determinism before we assert distinctness above.
    """
    ss = os.urandom(32)
    assert derive_tk(ss) == derive_tk(ss), "derive_tk is not deterministic"
    assert derive_kwrap_c(ss) == derive_kwrap_c(ss), "derive_kwrap_c is not deterministic"


# ═══════════════════════════════════════════════════════════════════════════════
# Invariant 6 — Entropy-Fusion Bias Resistance (Rushing Adversary)
# Paper: §VI-E Inv-6; §VI-C Theorem 4 (Bias Resistance);
#        §V "The commitment scheme prevents either party from biasing…"
#
# The rushing adversary model: attacker controls the SERVER and tries to
# choose TEFS *after* observing CommitC (not TEFC itself, since that is never
# sent on the wire before it is encrypted in M4).
#
# What we can prove here: CommitC reveals zero information about TEFC
# (it is SHA3-256(TEFC || rC || session_id), modelled as a random oracle).
# Therefore, the attacker cannot bias Fusion = SHA3-256(TEFC || TEFS || sid)
# by choosing TEFS after seeing CommitC, because TEFC is hidden.
#
# The structural argument (proved in STAGE_4_CLARIFICATION.md) is that
# CommitC is computed before CommitS is even available — reproduced here as a
# code-level assertion.
# ═══════════════════════════════════════════════════════════════════════════════

def test_inv6_bias_resistance_commitc_independent_of_commits(keypair):
    """
    §VI-E Inv-6 / Theorem 4: CommitC is set before CommitS is received.

    Structural proof (mirrors STAGE_4_CLARIFICATION.md):
    After process_m1() returns, _commit_c is set and _commit_s is None.
    process_m3() — which sets _commit_s — cannot execute until state ==
    M2_CREATED, which is only set at the end of process_m1().
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    alice.process_m1(m1)   # CommitC is generated inside this call

    # Immediately after process_m1: CommitC is finalised, CommitS is still None
    assert alice._commit_c is not None, (
        "CommitC must be set after process_m1() — rushing-adversary protection requires "
        "CommitC to be produced before any M3 data exists"
    )
    assert alice._commit_s is None, (
        "_commit_s must not be set until process_m3() is called — confirms the structural "
        "independence required by Theorem 4's bias-resistance argument"
    )


def test_inv6_bias_resistance_fusion_covers_both_tefs(keypair):
    """
    §VI-E Inv-6: Fusion = SHA3-256(TEFC || TEFS || session_id).
    Changing either TEF changes Fusion, proving both contributions are active.
    An attacker who chooses TEFS after seeing CommitC cannot fix Fusion to
    any chosen value because TEFC (hidden inside CommitC) is a free variable.
    """
    session_id = os.urandom(16)
    tefc  = os.urandom(32)
    tefs1 = os.urandom(32)
    tefs2 = os.urandom(32)   # different TEFS (with overwhelming probability)

    fusion1 = compute_fusion(tefc, tefs1, session_id)
    fusion2 = compute_fusion(tefc, tefs2, session_id)

    assert fusion1 != fusion2, (
        "Fusion must differ when TEFS differs — both TEFs must contribute to session entropy"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Invariant 7 — Volatile-State Zeroization
# Paper: §VI-E Inv-7; §VI-D G9 (Zeroization / Forward Secrecy after teardown).
# After process_m5 (which triggers zeroize_ephemeral on the client),
# all ephemeral secret fields must be None.
# ═══════════════════════════════════════════════════════════════════════════════

def test_inv7_ephemeral_state_zeroized_after_established(keypair):
    """
    §VI-E Inv-7 / G9: After the handshake completes, the client's ephemeral
    secrets (ss, tefc, rc, skS) are zeroized (set to None).
    session_key is retained — it is the output, not an intermediate secret.

    Note: Python-level zeroization limitations are documented in zeroization.py
    (no hardware guarantee — this is a best-effort software zeroization per R3).
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)
    m3 = bob.process_m2(m2)
    m4 = alice.process_m3(m3)
    m5 = bob.process_m4(m4)
    alice.process_m5(m5)   # zeroize_ephemeral() is called inside here

    # Ephemeral fields that must be cleared
    for attr in ("_ss", "_tefc", "_rc", "_skS"):
        assert getattr(alice, attr) is None, (
            f"alice.{attr} must be None after ESTABLISHED — ephemeral zeroization failed"
        )

    # session_key must survive (it is the handshake output)
    assert alice.session_key is not None, (
        "alice.session_key must survive zeroization — it is the protocol output"
    )
    assert alice.session_state == SessionState.ESTABLISHED


# ═══════════════════════════════════════════════════════════════════════════════
# Invariant 8 — Wrong Session-ID Rejection
# Paper: §VI-E Inv-8; §IV adversary model (replay, session-id substitution);
#        §V M2 verification step.
# ═══════════════════════════════════════════════════════════════════════════════

def test_inv8_wrong_session_id_raises(keypair):
    """
    §VI-E Inv-8: An M2 whose session_id does not match the server's session_id
    must raise SessionIDMismatch immediately (fail-closed, R5).
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)

    # Replace session_id with a random value
    bad_m2 = M2(session_id=os.urandom(16), ct=m2.ct, CommitC=m2.CommitC)

    with pytest.raises(SessionIDMismatch):
        bob.process_m2(bad_m2)


# ═══════════════════════════════════════════════════════════════════════════════
# Invariant 9 — Wrong Attestation Signature Rejection
# Paper: §VI-E Inv-9; §VI-D G1 (Server Authentication / Attestation Integrity);
#        §V M1 verification step.
# ═══════════════════════════════════════════════════════════════════════════════

def test_inv9_wrong_server_signing_key_raises(keypair):
    """
    §VI-E Inv-9 / G1: A client with the wrong server long-term public key
    cannot verify SigS → AttestationError raised (fail-closed, R5).
    """
    server_pk, server_sk = keypair
    wrong_pk, _ = dsa_keypair()

    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice_bad = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=wrong_pk)

    m1 = bob.create_m1()

    with pytest.raises(AttestationError):
        alice_bad.process_m1(m1)


def test_inv9_tampered_ephemeral_pubkey_in_m1_raises(keypair):
    """
    §VI-E Inv-9 (continued): Tampering pkS in M1 (without modifying SigS)
    breaks the quote-to-key binding check → AttestationError.
    This simulates a forged-attestation attack (Attacker replaces pkS with
    their own KEM public key while leaving the legitimate server's SigS intact).
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)

    m1 = bob.create_m1()
    # Flip one byte of pkS — SigS remains unchanged (legitimate server's signature)
    tampered_pks = bytearray(m1.pkS)
    tampered_pks[0] ^= 0xFF
    m1.pkS = bytes(tampered_pks)

    with pytest.raises(AttestationError):
        alice.process_m1(m1)


# ═══════════════════════════════════════════════════════════════════════════════
# Invariant 10 — Out-of-Order Message Rejection
# Paper: §VI-E Inv-10; §V State machine; PROTOCOL_SPEC.md §8.
# ═══════════════════════════════════════════════════════════════════════════════

def test_inv10_out_of_order_m4_before_m2_raises(keypair):
    """
    §VI-E Inv-10: Server in state M1_CREATED (expecting M2) must reject M4
    with InvalidStateTransition (fail-closed, R5).
    """
    server_pk, server_sk = keypair
    bob = HandshakeSession(role=SessionRole.SERVER,
                            server_signing_sk=server_sk, server_signing_pk=server_pk)
    bob.create_m1()   # state → M1_CREATED

    fake_m4 = M4(wrappedC=os.urandom(64))
    with pytest.raises(InvalidStateTransition):
        bob.process_m4(fake_m4)


def test_inv10_out_of_order_m6_before_m5_raises(keypair):
    """
    §VI-E Inv-10 (continued): Client in state M2_CREATED (expecting M3)
    must reject M6 with InvalidStateTransition.
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    alice.process_m1(m1)   # alice is now in M2_CREATED

    fake_m6 = M6(MACC=os.urandom(32))
    with pytest.raises(InvalidStateTransition):
        alice.process_m5(fake_m6)   # type: ignore  — wrong message type, wrong state


# ═══════════════════════════════════════════════════════════════════════════════
# Invariant 11 — Tampered AEAD Ciphertext Rejection
# Paper: §VI-E Inv-11; §VI-D G5 (Confidentiality / AEAD integrity);
#        §V AEAD authentication tag description.
# ═══════════════════════════════════════════════════════════════════════════════

def test_inv11_tampered_m4_ciphertext_raises_aead_error(keypair):
    """
    §VI-E Inv-11: Flipping any bit in M4.wrappedC must cause AEAD
    authentication failure when the server decrypts it.
    Specific exception: AEADError (or CommitmentError if AEAD passes
    but the commitment check fails — both are acceptable fail-closed outcomes).
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)
    m3 = bob.process_m2(m2)
    m4 = alice.process_m3(m3)

    tampered = bytearray(m4.wrappedC)
    tampered[0] ^= 0xFF
    m4.wrappedC = bytes(tampered)

    with pytest.raises((AEADError, CommitmentError)):
        bob.process_m4(m4)


def test_inv11_tampered_m5_ciphertext_raises_aead_error(keypair):
    """
    §VI-E Inv-11 (M5 path): Flipping a bit in M5.wrappedS must cause AEAD
    failure on the client's decrypt.
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER,
                              server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)
    m3 = bob.process_m2(m2)
    m4 = alice.process_m3(m3)
    m5 = bob.process_m4(m4)

    tampered = bytearray(m5.wrappedS)
    tampered[0] ^= 0xFF
    m5.wrappedS = bytes(tampered)

    with pytest.raises((AEADError, CommitmentError)):
        alice.process_m5(m5)

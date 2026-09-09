"""Protocol tests — M1-M6 happy path + malformed input + state machine rejection."""
import pytest
import os
from backend.crypto.dsa import generate_keypair as dsa_keypair
from backend.protocol.session import HandshakeSession
from backend.protocol.state_machine import SessionRole, SessionState, InvalidStateTransition
from backend.protocol.errors import AttestationError, MACError, CommitmentError, AEADError, SessionIDMismatch
from backend.protocol.messages import M2, M4, M6
from backend.protocol import m1 as _m1, m2 as _m2, m3 as _m3


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def keypair():
    return dsa_keypair()


@pytest.fixture
def full_handshake(keypair):
    """Run a complete handshake and return (alice, bob, all_messages)."""
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER, server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)
    m3 = bob.process_m2(m2)
    m4 = alice.process_m3(m3)
    m5 = bob.process_m4(m4)
    m6 = alice.process_m5(m5)
    bob.process_m6(m6)
    return alice, bob, dict(m1=m1, m2=m2, m3=m3, m4=m4, m5=m5, m6=m6)


# ─── Happy path: full handshake ───────────────────────────────────────────────

def test_full_handshake_session_keys_match(full_handshake):
    alice, bob, _ = full_handshake
    assert alice.session_key == bob.session_key
    assert alice.session_key is not None
    assert len(alice.session_key) == 32


def test_full_handshake_both_established(full_handshake):
    alice, bob, _ = full_handshake
    assert alice.session_state == SessionState.ESTABLISHED
    assert bob.session_state   == SessionState.ESTABLISHED


# ─── M1 tests ────────────────────────────────────────────────────────────────

def test_m1_invalid_signature_raises(keypair):
    server_pk, server_sk = keypair
    wrong_pk, _ = dsa_keypair()
    bob = HandshakeSession(role=SessionRole.SERVER, server_signing_sk=server_sk, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    # Client with wrong server key
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=wrong_pk)
    with pytest.raises(AttestationError):
        alice.process_m1(m1)


def test_m1_tampered_pks_raises(keypair):
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER, server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    # Tamper pkS — breaks quote binding check
    tampered = bytearray(m1.pkS); tampered[0] ^= 0xFF
    m1.pkS = bytes(tampered)
    with pytest.raises(AttestationError):
        alice.process_m1(m1)


# ─── M2 tests ────────────────────────────────────────────────────────────────

def test_m2_wrong_session_id_raises(keypair):
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER, server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)
    bad_m2 = M2(session_id=os.urandom(16), ct=m2.ct, CommitC=m2.CommitC)
    with pytest.raises(SessionIDMismatch):
        bob.process_m2(bad_m2)


# ─── M3 tests ────────────────────────────────────────────────────────────────

def test_m3_bad_mac1_raises(keypair):
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER, server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)
    m3 = bob.process_m2(m2)
    # Tamper MAC1
    tampered = bytearray(m3.MAC1); tampered[0] ^= 0xFF
    m3.MAC1 = bytes(tampered)
    with pytest.raises(MACError):
        alice.process_m3(m3)


# ─── M4 tests ────────────────────────────────────────────────────────────────

def test_m4_tampered_ciphertext_raises(keypair):
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER, server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)
    m3 = bob.process_m2(m2)
    m4 = alice.process_m3(m3)
    tampered = bytearray(m4.wrappedC); tampered[-1] ^= 0xFF
    m4.wrappedC = bytes(tampered)
    with pytest.raises((AEADError, CommitmentError)):
        bob.process_m4(m4)


# ─── M5 tests ────────────────────────────────────────────────────────────────

def test_m5_tampered_macs_raises(keypair):
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER, server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)
    m3 = bob.process_m2(m2)
    m4 = alice.process_m3(m3)
    m5 = bob.process_m4(m4)
    tampered = bytearray(m5.MACS); tampered[0] ^= 0xFF
    m5.MACS = bytes(tampered)
    with pytest.raises(MACError):
        alice.process_m5(m5)


# ─── M6 tests ────────────────────────────────────────────────────────────────

def test_m6_tampered_macc_raises(keypair):
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER, server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    m2 = alice.process_m1(m1)
    m3 = bob.process_m2(m2)
    m4 = alice.process_m3(m3)
    m5 = bob.process_m4(m4)
    m6 = alice.process_m5(m5)
    tampered = bytearray(m6.MACC); tampered[0] ^= 0xFF
    m6.MACC = bytes(tampered)
    with pytest.raises(MACError):
        bob.process_m6(m6)


# ─── State machine rejection ──────────────────────────────────────────────────

def test_out_of_order_m4_before_m3_raises(keypair):
    """Feeding M4 when server expects M2 must raise InvalidStateTransition."""
    server_pk, server_sk = keypair
    bob = HandshakeSession(role=SessionRole.SERVER, server_signing_sk=server_sk, server_signing_pk=server_pk)
    bob.create_m1()  # state → M1_CREATED
    fake_m4 = M4(wrappedC=b"\x00" * 50)
    with pytest.raises(InvalidStateTransition):
        bob.process_m4(fake_m4)


def test_commit_before_reveal_structural(keypair):
    """
    Verify CommitC is computed in process_m1() (before client has seen M3 / CommitS).
    CommitC must be set on the client session BEFORE process_m3 is ever called.
    """
    server_pk, server_sk = keypair
    bob   = HandshakeSession(role=SessionRole.SERVER, server_signing_sk=server_sk, server_signing_pk=server_pk)
    alice = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
    m1 = bob.create_m1()
    alice.process_m1(m1)
    # CommitC must already be set — M3 (CommitS) has NOT been received yet
    assert alice._commit_c is not None, "CommitC must be set before M3 is processed"
    assert alice._commit_s is None,     "CommitS must NOT yet be set at this point"

"""
HandshakeSession — orchestrates M1-M6 for a single endpoint.

Each side (client/server) is an independent HandshakeSession instance.
All inter-side communication must pass through the caller (or network simulator in Stage 6).
Direct calls between alice and bob session objects are prohibited (ARCHITECTURE.md §2).
"""
import os
from backend.protocol.state_machine import SessionRole, SessionState, InvalidStateTransition, require_state, advance
from backend.protocol.transcript import TranscriptManager
from backend.protocol.messages import M1, M2, M3, M4, M5, M6
from backend.protocol import m1 as _m1, m2 as _m2, m3 as _m3, m4 as _m4, m5 as _m5, m6 as _m6
from backend.crypto.kem import generate_keypair as kem_keypair
from backend.shm.software_shm import SoftwareSHM


class HandshakeSession:
    """
    Manages one side of a TAKD-PQE handshake.

    Usage (server):
        sess = HandshakeSession(role=SessionRole.SERVER, server_signing_sk=sk, server_signing_pk=pk)
        msg1 = sess.create_m1()
        msg3 = sess.process_m2(msg2_from_client)
        msg5 = sess.process_m4(msg4_from_client)
        sess.process_m6(msg6_from_client)
        key = sess.session_key

    Usage (client):
        sess = HandshakeSession(role=SessionRole.CLIENT, server_signing_pk=server_pk)
        msg2 = sess.process_m1(msg1_from_server)
        msg4 = sess.process_m3(msg3_from_server)
        msg6 = sess.process_m5(msg5_from_server)
        key = sess.session_key
    """

    def __init__(
        self,
        role: SessionRole,
        server_signing_pk: bytes,
        server_signing_sk: bytes = None,   # only required for server role
        shm: SoftwareSHM = None,
        session_id: bytes = None,
    ):
        self.role = role
        self.state = SessionState.INIT
        self._shm = shm or SoftwareSHM()
        self._server_signing_pk = server_signing_pk
        self._server_signing_sk = server_signing_sk  # server only
        self.session_id: bytes = session_id           # set by server in create_m1; received by client in process_m1

        # Ephemeral secrets (zeroized after ESTABLISHED)
        self._pkS: bytes = None
        self._skS: bytes = None
        self._ss: bytes = None
        self._tefc: bytes = None
        self._rc: bytes = None
        self._tefs: bytes = None
        self._rs: bytes = None
        self._commit_c: bytes = None
        self._commit_s: bytes = None
        self._th5: bytes = None
        self._m5_ref: M5 = None        # kept to compute TH6

        # Final output
        self.session_key: bytes = None
        self.session_state = self.state

        # Transcript is initialised once session_id is known
        self._transcript: TranscriptManager = None

    def _init_transcript(self, session_id: bytes):
        self._transcript = TranscriptManager(session_id)

    def _transition(self, expected_from: SessionState) -> SessionState:
        require_state(self.state, expected_from, f"transition from {expected_from.value}")
        self.state = advance(self.state, self.role)
        self.session_state = self.state
        return self.state

    # ------------------------------------------------------------------ SERVER

    def create_m1(self) -> M1:
        """SERVER: INIT → M1_CREATED."""
        self._transition(SessionState.INIT)
        self.session_id = os.urandom(16)
        self._pkS, self._skS = kem_keypair()
        self._init_transcript(self.session_id)
        msg = _m1.build_m1(self.session_id, self._pkS, self._server_signing_sk, self._shm)
        self._transcript.update(msg)
        return msg

    def process_m2(self, msg: M2) -> M3:
        """SERVER: M1_CREATED → M2_VERIFIED → M3_CREATED."""
        self._transition(SessionState.M1_CREATED)
        _m2.verify_m2(msg, self.session_id)
        self._commit_c = msg.CommitC
        self._transcript.update(msg)
        th2 = self._transcript.current

        self._transition(SessionState.M2_VERIFIED)
        m3_msg, ss, tefs, rs, _ = _m3.build_m3(self.session_id, msg.ct, self._skS, th2, self._shm)
        self._ss = ss
        self._tefs = tefs
        self._rs = rs
        self._commit_s = m3_msg.CommitS
        self._transcript.update(m3_msg)
        return m3_msg

    def process_m4(self, msg: M4) -> M5:
        """SERVER: M3_CREATED → M4_VERIFIED → M5_CREATED."""
        self._transition(SessionState.M3_CREATED)
        th3 = self._transcript.current
        tefc, rc = _m4.verify_m4(msg, self._ss, self._commit_c, self.session_id, th3)
        self._tefc = tefc
        self._transcript.update(msg)
        th4 = self._transcript.current

        self._transition(SessionState.M4_VERIFIED)
        m5_msg, fusion, sk, th5 = _m5.build_m5(self._ss, self._tefs, self._rs, tefc, self.session_id, th4)
        self.session_key = sk
        self._th5 = th5
        self._m5_ref = m5_msg
        # TH5 was computed over M5-minus-MACS; now update transcript with the partial dict
        # to keep TH consistent: we advance transcript by the partial M5 (no MACS)
        self._transcript.update_partial(m5_msg.to_dict_without_macs())
        return m5_msg

    def process_m6(self, msg: M6) -> None:
        """SERVER: M5_CREATED → ESTABLISHED."""
        self._transition(SessionState.M5_CREATED)
        _m6.verify_m6(msg, self.session_key, self._m5_ref, self._th5)
        self._zeroize_ephemeral()
        self.state = SessionState.ESTABLISHED
        self.session_state = self.state

    # ------------------------------------------------------------------ CLIENT

    def process_m1(self, msg: M1) -> M2:
        """CLIENT: INIT → M1_VERIFIED → M2_CREATED."""
        self._transition(SessionState.INIT)
        _m1.verify_m1(msg, self._server_signing_pk)
        self.session_id = msg.session_id
        self._init_transcript(self.session_id)
        self._transcript.update(msg)

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
        self._ss = ss
        self._tefc = tefc
        self._rc = rc
        self._commit_c = m2_msg.CommitC
        self._transcript.update(m2_msg)
        return m2_msg

    def process_m3(self, msg: M3) -> M4:
        """CLIENT: M2_CREATED → M3_VERIFIED → M4_CREATED."""
        self._transition(SessionState.M2_CREATED)
        th2 = self._transcript.current
        _m3.verify_m3(msg, self._ss, th2)
        self._commit_s = msg.CommitS
        self._transcript.update(msg)
        th3 = self._transcript.current

        self._transition(SessionState.M3_VERIFIED)
        m4_msg = _m4.build_m4(self._ss, self._tefc, self._rc, th3)
        self._transcript.update(m4_msg)
        return m4_msg

    def process_m5(self, msg: M5) -> M6:
        """CLIENT: M4_CREATED → M5_VERIFIED → ESTABLISHED."""
        self._transition(SessionState.M4_CREATED)
        th4 = self._transcript.current
        sk, fusion, th5 = _m5.verify_m5(msg, self._ss, self._commit_s, self.session_id, th4, self._tefc)
        self.session_key = sk
        self._th5 = th5
        self._m5_ref = msg
        # Mirror server: advance transcript by partial M5
        self._transcript.update_partial(msg.to_dict_without_macs())

        self._transition(SessionState.M5_VERIFIED)
        m6_msg, th6 = _m6.build_m6(sk, msg, th5)
        self._zeroize_ephemeral()
        self.state = SessionState.ESTABLISHED
        self.session_state = self.state
        return m6_msg

    # ------------------------------------------------------------------ HELPERS

    def _zeroize_ephemeral(self):
        """Best-effort zeroization of ephemeral handshake secrets (R3, R6)."""
        for attr in ("_ss", "_tefc", "_rc", "_tefs", "_rs", "_skS"):
            val = getattr(self, attr, None)
            if isinstance(val, bytearray):
                for i in range(len(val)):
                    val[i] = 0
            setattr(self, attr, None)

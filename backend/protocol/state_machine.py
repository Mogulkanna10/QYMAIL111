"""State machine for TAKD-PQE handshake — PROTOCOL_SPEC.md §8."""
from enum import Enum


class SessionRole(Enum):
    CLIENT = "client"
    SERVER = "server"


class SessionState(Enum):
    INIT = "INIT"
    M1_CREATED = "M1_CREATED"
    M1_VERIFIED = "M1_VERIFIED"
    M2_CREATED = "M2_CREATED"
    M2_VERIFIED = "M2_VERIFIED"
    M3_CREATED = "M3_CREATED"
    M3_VERIFIED = "M3_VERIFIED"
    M4_CREATED = "M4_CREATED"
    M4_VERIFIED = "M4_VERIFIED"
    M5_CREATED = "M5_CREATED"
    M5_VERIFIED = "M5_VERIFIED"
    M6_CREATED = "M6_CREATED"
    ESTABLISHED = "ESTABLISHED"
    EMAIL_SECURE = "EMAIL_SECURE"
    TEARDOWN = "TEARDOWN"
    ZEROIZED = "ZEROIZED"


class InvalidStateTransition(Exception):
    """Raised when a message arrives or action is attempted out of sequence (R5)."""
    pass


# Valid (from_state, to_state) transitions per role.
# Any pair NOT in this table must raise InvalidStateTransition.
_SERVER_TRANSITIONS = {
    SessionState.INIT:        SessionState.M1_CREATED,
    SessionState.M1_CREATED:  SessionState.M2_VERIFIED,
    SessionState.M2_VERIFIED: SessionState.M3_CREATED,
    SessionState.M3_CREATED:  SessionState.M4_VERIFIED,
    SessionState.M4_VERIFIED: SessionState.M5_CREATED,
    SessionState.M5_CREATED:  SessionState.ESTABLISHED,
    SessionState.ESTABLISHED: SessionState.EMAIL_SECURE,
    SessionState.EMAIL_SECURE: SessionState.TEARDOWN,
    SessionState.TEARDOWN:    SessionState.ZEROIZED,
}

_CLIENT_TRANSITIONS = {
    SessionState.INIT:        SessionState.M1_VERIFIED,
    SessionState.M1_VERIFIED: SessionState.M2_CREATED,
    SessionState.M2_CREATED:  SessionState.M3_VERIFIED,
    SessionState.M3_VERIFIED: SessionState.M4_CREATED,
    SessionState.M4_CREATED:  SessionState.M5_VERIFIED,
    SessionState.M5_VERIFIED: SessionState.ESTABLISHED,
    SessionState.ESTABLISHED: SessionState.EMAIL_SECURE,
    SessionState.EMAIL_SECURE: SessionState.TEARDOWN,
    SessionState.TEARDOWN:    SessionState.ZEROIZED,
}


def advance(current: SessionState, role: SessionRole) -> SessionState:
    """
    Return the next valid state for the given role.
    Raises InvalidStateTransition if the current state has no valid successor.
    """
    table = _SERVER_TRANSITIONS if role == SessionRole.SERVER else _CLIENT_TRANSITIONS
    nxt = table.get(current)
    if nxt is None:
        raise InvalidStateTransition(
            f"No valid transition from state {current.value} for role {role.value}"
        )
    return nxt


def require_state(current: SessionState, expected: SessionState, action: str) -> None:
    """Assert that the session is in the expected state before an action. Raises on mismatch."""
    if current != expected:
        raise InvalidStateTransition(
            f"Action '{action}' requires state {expected.value}, but current state is {current.value}"
        )

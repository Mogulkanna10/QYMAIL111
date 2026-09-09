"""TAKD-PQE Message Wire Format Models — matches PROTOCOL_SPEC.md §2 field-for-field."""
from dataclasses import dataclass, field


@dataclass
class M1:
    """Server → Client. §2 M1."""
    session_id: bytes      # 16 B
    TS: int
    pkS: bytes             # 1568 B  ephemeral ML-KEM-1024 public key
    quote: dict            # {device_id, firmware_hash, ephemeral_kem_public_key, session_id, timestamp}
    SigS: bytes            # 4627 B  ML-DSA-87 over SHA3-256(canonical(quote))

    def to_dict(self) -> dict:
        return {"session_id": self.session_id, "TS": self.TS,
                "pkS": self.pkS, "quote": self.quote, "SigS": self.SigS}


@dataclass
class M2:
    """Client → Server. §2 M2."""
    session_id: bytes      # 16 B
    ct: bytes              # 1568 B  KEM.Encaps(pkS) ciphertext
    CommitC: bytes         # 32 B   SHA3-256(TEFC || rC || session_id)

    def to_dict(self) -> dict:
        return {"session_id": self.session_id, "ct": self.ct, "CommitC": self.CommitC}


@dataclass
class M3:
    """Server → Client. §2 M3."""
    CommitS: bytes         # 32 B   SHA3-256(TEFS || rS || session_id)
    MAC1: bytes            # HMAC(TK, "commit" || TH2)

    def to_dict(self) -> dict:
        return {"CommitS": self.CommitS, "MAC1": self.MAC1}


@dataclass
class M4:
    """Client → Server. §2 M4."""
    wrappedC: bytes        # AEAD.Encrypt(Kwrap_C, TEFC||rC, AD=TH3)

    def to_dict(self) -> dict:
        return {"wrappedC": self.wrappedC}


@dataclass
class M5:
    """Server → Client. §2 M5."""
    wrappedS: bytes        # AEAD.Encrypt(Kwrap_S, TEFS||rS, AD=TH4)
    MACS: bytes            # HMAC(SessionKey, "confirm-S" || TH5)

    def to_dict(self) -> dict:
        return {"wrappedS": self.wrappedS, "MACS": self.MACS}

    def to_dict_without_macs(self) -> dict:
        """Returns {wrappedS} only — used when computing TH5 (MACS cannot hash itself)."""
        return {"wrappedS": self.wrappedS}


@dataclass
class M6:
    """Client → Server. §2 M6."""
    MACC: bytes            # HMAC(SessionKey, "confirm-C" || TH6)

    def to_dict(self) -> dict:
        return {"MACC": self.MACC}

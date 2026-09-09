"""
Abstract interface for the Secure Hardware Module (SHM).

IMPORTANT (Global Rule R3): This interface defines the contract for hardware-level
security operations. In this prototype, the only concrete implementation is
SoftwareSHM (software_shm.py), which EMULATES this behavior using OS entropy
sources and in-process operations. It does NOT represent genuine hardware security,
hardware TRNG, hardware attestation, or hardware-guaranteed zeroization.
"""

from abc import ABC, abstractmethod


class SecureHardwareModule(ABC):
    """
    Abstract base class representing the SHM trusted domain.

    NOTE (R3): All implementations in this prototype are software emulations.
    Never claim genuine hardware behavior through this interface.
    """

    @abstractmethod
    def generate_tef(self, session_id: bytes) -> tuple[bytes, bytes]:
        """
        Generate a Trusted Entropy Fragment (TEF) and its blinding nonce.

        Returns:
            (tef: bytes(32), r: bytes(16)) — both freshly sampled, health-tested.

        NOTE (R3): In SoftwareSHM, this is SOFTWARE EMULATION of hardware TRNG output.
        """
        ...

    @abstractmethod
    def health_test(self, sample: bytes) -> bool:
        """
        Run SP 800-90B-style statistical health tests on a byte sample.

        Returns True if the sample passes all tests, False if it fails.
        A False return MUST cause the caller to abort or resample (R5: fail closed).
        """
        ...

    @abstractmethod
    def generate_kem_keypair(self) -> tuple[bytes, bytes]:
        """
        Generate an ephemeral ML-KEM-1024 keypair via the SHM trusted domain.

        Returns:
            (public_key: bytes, secret_key: bytes)

        NOTE (R3): In SoftwareSHM, key generation uses standard OS entropy,
        not a hardware-isolated TRNG.
        """
        ...

    @abstractmethod
    def get_attestation_quote(
        self,
        device_id: str,
        firmware_hash: bytes,
        ephemeral_kem_public_key: bytes,
        session_id: bytes,
        timestamp: int,
    ) -> dict:
        """
        Build an attestation quote binding the ephemeral KEM public key to this device.

        Returns a dict with fields: device_id, firmware_hash, ephemeral_kem_public_key,
        session_id, timestamp.

        NOTE (R3): In SoftwareSHM, this is SOFTWARE EMULATION of TPM-style attestation.
        """
        ...

    @abstractmethod
    def sign_attestation(self, quote: dict, signing_sk: bytes) -> bytes:
        """
        Sign SHA3-256(canonical(quote)) using ML-DSA-87 with the given secret key.

        Returns the signature bytes.
        """
        ...

    @abstractmethod
    def secure_store(self, key: str, value: bytes) -> None:
        """
        Store a secret value under a named key in the SHM protected memory region.

        NOTE (R3): In SoftwareSHM, this is an IN-PROCESS dictionary — not hardware-isolated.
        """
        ...

    @abstractmethod
    def zeroize(self, key: str) -> None:
        """
        Overwrite and discard a stored secret.

        NOTE (R3): In SoftwareSHM, zeroization is BEST-EFFORT only. Python's garbage
        collector and string immutability mean there is NO hardware-level guarantee
        that the memory is cleared.
        """
        ...

"""
pqc_abstract.py — Post-Quantum Cryptography Abstract Layer
===========================================================
A clean, Pythonic wrapper around the ``oqs`` (liboqs-python) package that
exposes KEM and SIG primitives through safe, self-documenting APIs.

Dependencies
------------
    pip install liboqs-python        # installs the ``oqs`` package
    # liboqs shared library must also be built and installed system-wide.
    # See: https://github.com/open-quantum-safe/liboqs

Quick start
-----------
    from pqc_abstract import KEM, SIG, PQCError

    # --- KEM round-trip ---
    kem = KEM()                          # defaults to ML-KEM-768
    alice = kem.keygen()
    enc   = kem.encaps(alice.public_key)
    ss    = kem.decaps(enc.ciphertext, alice.secret_key)
    assert enc.shared_secret == ss

    # --- SIG round-trip ---
    sig   = SIG()                        # defaults to ML-DSA-65
    keys  = sig.keygen()
    s     = sig.sign(b"hello world", keys.secret_key)
    ok    = sig.verify(b"hello world", s, keys.public_key)

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import importlib
import secrets
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Lazy import of the ``oqs`` package so that import of *this* module does not
# crash in environments where liboqs is not installed.
# ---------------------------------------------------------------------------
def _require_oqs():
    try:
        import oqs  # noqa: F401 – checked below
    except ImportError as exc:
        raise ImportError(
            "The 'oqs' package (liboqs-python) is required. "
            "Install with:  pip install liboqs-python"
        ) from exc
    return importlib.import_module("oqs")


# ═══════════════════════════════════════════════════════════════════════════
# Exceptions
# ═══════════════════════════════════════════════════════════════════════════

class PQCError(Exception):
    """Base class for all pqc_abstract errors."""


class AlgorithmNotAvailable(PQCError):
    """Raised when a requested algorithm is unknown or disabled at build time."""


class KeygenError(PQCError):
    """Raised when key generation fails."""


class EncapsulationError(PQCError):
    """Raised when KEM encapsulation fails."""


class DecapsulationError(PQCError):
    """Raised when KEM decapsulation fails."""


class SigningError(PQCError):
    """Raised when signing fails."""


class VerificationError(PQCError):
    """Raised when signature verification fails (invalid signature)."""


# ═══════════════════════════════════════════════════════════════════════════
# Well-known algorithm names
# ═══════════════════════════════════════════════════════════════════════════

class KEMAlgorithm:
    """String constants for KEM algorithm names."""
    DEFAULT        = "ML-KEM-768"

    ML_KEM_512     = "ML-KEM-512"
    ML_KEM_768     = "ML-KEM-768"
    ML_KEM_1024    = "ML-KEM-1024"

    KYBER_512      = "Kyber512"
    KYBER_768      = "Kyber768"
    KYBER_1024     = "Kyber1024"

    BIKE_L1        = "BIKE-L1"
    BIKE_L3        = "BIKE-L3"
    BIKE_L5        = "BIKE-L5"

    FRODO_640_AES  = "FrodoKEM-640-AES"
    FRODO_640_SHAKE= "FrodoKEM-640-SHAKE"
    FRODO_976_AES  = "FrodoKEM-976-AES"
    FRODO_976_SHAKE= "FrodoKEM-976-SHAKE"

    HQC_1          = "HQC-1"
    HQC_3          = "HQC-3"
    HQC_5          = "HQC-5"


class SIGAlgorithm:
    """String constants for signature algorithm names."""
    DEFAULT        = "ML-DSA-65"

    ML_DSA_44      = "ML-DSA-44"
    ML_DSA_65      = "ML-DSA-65"
    ML_DSA_87      = "ML-DSA-87"

    FALCON_512     = "Falcon-512"
    FALCON_1024    = "Falcon-1024"
    FALCON_PADDED_512  = "Falcon-padded-512"
    FALCON_PADDED_1024 = "Falcon-padded-1024"

    MAYO_1         = "MAYO-1"
    MAYO_2         = "MAYO-2"
    MAYO_3         = "MAYO-3"
    MAYO_5         = "MAYO-5"


# ═══════════════════════════════════════════════════════════════════════════
# Data classes — returned by API methods
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class KEMKeyPair:
    """Holds a KEM public/secret key pair."""
    public_key: bytes
    secret_key: bytes

    def __repr__(self) -> str:
        return (
            f"KEMKeyPair(pk={self.public_key[:8].hex()}… [{len(self.public_key)} B], "
            f"sk=<{len(self.secret_key)} B hidden>)"
        )

    def wipe(self) -> None:
        """Best-effort in-memory zeroise (note: Python GC may keep copies)."""
        object.__setattr__(self, "secret_key", bytes(len(self.secret_key)))


@dataclass
class KEMEncapsResult:
    """Result of a KEM encapsulation operation."""
    ciphertext:    bytes
    shared_secret: bytes

    def __repr__(self) -> str:
        return (
            f"KEMEncapsResult(ct={self.ciphertext[:8].hex()}… [{len(self.ciphertext)} B], "
            f"ss={self.shared_secret[:8].hex()}… [{len(self.shared_secret)} B])"
        )

    def wipe(self) -> None:
        object.__setattr__(self, "shared_secret", bytes(len(self.shared_secret)))


@dataclass
class SIGKeyPair:
    """Holds a SIG public/secret key pair."""
    public_key: bytes
    secret_key: bytes

    def __repr__(self) -> str:
        return (
            f"SIGKeyPair(pk={self.public_key[:8].hex()}… [{len(self.public_key)} B], "
            f"sk=<{len(self.secret_key)} B hidden>)"
        )

    def wipe(self) -> None:
        object.__setattr__(self, "secret_key", bytes(len(self.secret_key)))


@dataclass
class AlgorithmInfo:
    """Algorithm metadata."""
    name:               str
    nist_level:         int
    public_key_length:  int
    secret_key_length:  int
    # KEM specific
    ciphertext_length:  Optional[int] = None
    shared_secret_length: Optional[int] = None
    ind_cca:            Optional[bool] = None
    # SIG specific
    max_signature_length: Optional[int] = None
    euf_cma:            Optional[bool] = None
    suf_cma:            Optional[bool] = None
    ctx_str_support:    Optional[bool] = None

    def __str__(self) -> str:
        lines = [f"Algorithm : {self.name}", f"  NIST level : {self.nist_level}"]
        lines.append(f"  Public key : {self.public_key_length} B")
        lines.append(f"  Secret key : {self.secret_key_length} B")
        if self.ciphertext_length is not None:
            lines.append(f"  Ciphertext : {self.ciphertext_length} B")
            lines.append(f"  Shared secret : {self.shared_secret_length} B")
            lines.append(f"  IND-CCA2 : {self.ind_cca}")
        if self.max_signature_length is not None:
            lines.append(f"  Max signature : {self.max_signature_length} B")
            lines.append(f"  EUF-CMA : {self.euf_cma}")
            lines.append(f"  SUF-CMA : {self.suf_cma}")
            lines.append(f"  Context strings : {self.ctx_str_support}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# KEM
# ═══════════════════════════════════════════════════════════════════════════

class KEM:
    """
    Post-Quantum Key Encapsulation Mechanism.

    Parameters
    ----------
    algorithm : str, optional
        liboqs algorithm name.  Defaults to ``KEMAlgorithm.DEFAULT``
        ("ML-KEM-768", NIST FIPS 203 level 3).

    Examples
    --------
    >>> kem   = KEM("ML-KEM-512")
    >>> keys  = kem.keygen()
    >>> enc   = kem.encaps(keys.public_key)
    >>> ss    = kem.decaps(enc.ciphertext, keys.secret_key)
    >>> assert enc.shared_secret == ss
    """

    def __init__(self, algorithm: str = KEMAlgorithm.DEFAULT) -> None:
        oqs = _require_oqs()
        self._algorithm = algorithm
        try:
            self._kem = oqs.KeyEncapsulation(algorithm)
        except Exception as exc:
            raise AlgorithmNotAvailable(
                f"KEM algorithm '{algorithm}' is not available. "
                "Check that liboqs was built with that algorithm enabled."
            ) from exc

    # ── Properties ──────────────────────────────────────────────────────────

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def info(self) -> AlgorithmInfo:
        d = self._kem.details
        return AlgorithmInfo(
            name=d["name"],
            nist_level=d["claimed_nist_level"],
            public_key_length=d["length_public_key"],
            secret_key_length=d["length_secret_key"],
            ciphertext_length=d["length_ciphertext"],
            shared_secret_length=d["length_shared_secret"],
            ind_cca=d["ind_cca"],
        )

    # ── Core API ─────────────────────────────────────────────────────────────

    def keygen(self) -> KEMKeyPair:
        """Generate a fresh KEM key pair.

        Returns
        -------
        KEMKeyPair
            Freshly generated public/secret key pair.

        Raises
        ------
        KeygenError
        """
        try:
            public_key = self._kem.generate_keypair()
            secret_key = self._kem.export_secret_key()
            return KEMKeyPair(public_key=bytes(public_key),
                              secret_key=bytes(secret_key))
        except Exception as exc:
            raise KeygenError(f"KEM keygen failed: {exc}") from exc

    def encaps(self, public_key: bytes) -> KEMEncapsResult:
        """Encapsulate: generate a ciphertext and shared secret.

        Parameters
        ----------
        public_key : bytes
            Recipient's public key (``info.public_key_length`` bytes).

        Returns
        -------
        KEMEncapsResult
            Contains ``ciphertext`` and ``shared_secret``.

        Raises
        ------
        EncapsulationError
        """
        try:
            # liboqs-python encap_secret returns (ciphertext, shared_secret)
            ciphertext, shared_secret = self._kem.encap_secret(public_key)
            return KEMEncapsResult(ciphertext=bytes(ciphertext),
                                   shared_secret=bytes(shared_secret))
        except Exception as exc:
            raise EncapsulationError(f"KEM encapsulation failed: {exc}") from exc

    def decaps(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate: recover the shared secret.

        Parameters
        ----------
        ciphertext : bytes
            Ciphertext from :meth:`encaps`.
        secret_key : bytes
            Recipient's secret key.

        Returns
        -------
        bytes
            Recovered shared secret (``info.shared_secret_length`` bytes).

        Raises
        ------
        DecapsulationError
        """
        try:
            # We need a fresh KEM object seeded with the secret key.
            oqs = _require_oqs()
            kem_dec = oqs.KeyEncapsulation(self._algorithm, secret_key)
            shared_secret = kem_dec.decap_secret(ciphertext)
            return bytes(shared_secret)
        except Exception as exc:
            raise DecapsulationError(f"KEM decapsulation failed: {exc}") from exc

    def __repr__(self) -> str:
        return f"KEM(algorithm={self._algorithm!r})"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._kem.free()


# ═══════════════════════════════════════════════════════════════════════════
# SIG
# ═══════════════════════════════════════════════════════════════════════════

class SIG:
    """
    Post-Quantum Digital Signature Scheme.

    Parameters
    ----------
    algorithm : str, optional
        liboqs algorithm name.  Defaults to ``SIGAlgorithm.DEFAULT``
        ("ML-DSA-65", NIST FIPS 204 level 3).

    Examples
    --------
    >>> sig  = SIG("Falcon-512")
    >>> keys = sig.keygen()
    >>> s    = sig.sign(b"hello", keys.secret_key)
    >>> assert sig.verify(b"hello", s, keys.public_key)
    """

    def __init__(self, algorithm: str = SIGAlgorithm.DEFAULT) -> None:
        oqs = _require_oqs()
        self._algorithm = algorithm
        try:
            self._sig = oqs.Signature(algorithm)
        except Exception as exc:
            raise AlgorithmNotAvailable(
                f"SIG algorithm '{algorithm}' is not available. "
                "Check that liboqs was built with that algorithm enabled."
            ) from exc

    # ── Properties ──────────────────────────────────────────────────────────

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def info(self) -> AlgorithmInfo:
        d = self._sig.details
        return AlgorithmInfo(
            name=d["name"],
            nist_level=d["claimed_nist_level"],
            public_key_length=d["length_public_key"],
            secret_key_length=d["length_secret_key"],
            max_signature_length=d["length_signature"],
            euf_cma=d["euf_cma"],
            suf_cma=d.get("suf_cma", False),
            ctx_str_support=d.get("sig_with_ctx_support", False),
        )

    # ── Core API ─────────────────────────────────────────────────────────────

    def keygen(self) -> SIGKeyPair:
        """Generate a fresh SIG key pair.

        Returns
        -------
        SIGKeyPair

        Raises
        ------
        KeygenError
        """
        try:
            public_key = self._sig.generate_keypair()
            secret_key = self._sig.export_secret_key()
            return SIGKeyPair(public_key=bytes(public_key),
                              secret_key=bytes(secret_key))
        except Exception as exc:
            raise KeygenError(f"SIG keygen failed: {exc}") from exc

    def sign(self,
             message: bytes,
             secret_key: bytes,
             *,
             ctx: Optional[bytes] = None) -> bytes:
        """Sign a message.

        Parameters
        ----------
        message : bytes
            Arbitrary message bytes.
        secret_key : bytes
            Signer's secret key.
        ctx : bytes, optional
            Context string (only for algorithms that support it,
            e.g. ML-DSA).  Silently ignored if the algorithm does
            not support context strings.

        Returns
        -------
        bytes
            The signature.

        Raises
        ------
        SigningError
        """
        try:
            oqs = _require_oqs()
            sig_obj = oqs.Signature(self._algorithm, secret_key)
            if ctx is not None and self.info.ctx_str_support:
                signature = sig_obj.sign_with_ctx_str(message, ctx)
            else:
                signature = sig_obj.sign(message)
            return bytes(signature)
        except Exception as exc:
            raise SigningError(f"Signing failed: {exc}") from exc

    def verify(self,
               message: bytes,
               signature: bytes,
               public_key: bytes,
               *,
               ctx: Optional[bytes] = None) -> bool:
        """Verify a signature.

        Parameters
        ----------
        message : bytes
            The original message.
        signature : bytes
            Signature produced by :meth:`sign`.
        public_key : bytes
            Signer's public key.
        ctx : bytes, optional
            Context string used during signing (must match).

        Returns
        -------
        bool
            ``True`` if the signature is valid.

        Raises
        ------
        VerificationError
            If the signature is definitively invalid (rather than just
            returning ``False``).
        """
        try:
            if ctx is not None and self.info.ctx_str_support:
                return bool(self._sig.verify_with_ctx_str(message, signature, ctx, public_key))
            return bool(self._sig.verify(message, signature, public_key))
        except Exception as exc:
            raise VerificationError(f"Verification error: {exc}") from exc

    def __repr__(self) -> str:
        return f"SIG(algorithm={self._algorithm!r})"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._sig.free()


# ═══════════════════════════════════════════════════════════════════════════
# Utility helpers
# ═══════════════════════════════════════════════════════════════════════════

def list_kem_algorithms(*, enabled_only: bool = True) -> list[str]:
    """Return names of available KEM algorithms.

    Parameters
    ----------
    enabled_only : bool
        If True (default), skip algorithms disabled at compile time.
    """
    oqs = _require_oqs()
    algs = oqs.get_enabled_kem_mechanisms() if enabled_only else oqs.get_supported_kem_mechanisms()
    return list(algs)


def list_sig_algorithms(*, enabled_only: bool = True) -> list[str]:
    """Return names of available SIG algorithms."""
    oqs = _require_oqs()
    algs = oqs.get_enabled_sig_mechanisms() if enabled_only else oqs.get_supported_sig_mechanisms()
    return list(algs)


def kem_info(algorithm: str) -> AlgorithmInfo:
    """Return metadata for a KEM algorithm without creating a full context."""
    return KEM(algorithm).info


def sig_info(algorithm: str) -> AlgorithmInfo:
    """Return metadata for a SIG algorithm without creating a full context."""
    return SIG(algorithm).info

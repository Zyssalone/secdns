"""
secdns.crypto -- cryptographic building blocks for SECDNS.

Design rule from the assignment: *use vetted primitives, do not invent
your own*. Every primitive here is a thin wrapper over `cryptography`
(which wraps OpenSSL). We add no custom cipher, KDF or signature scheme.

Primitives chosen and why
-------------------------
* Ed25519 (RFC 8032) for the trust chain (anchor -> zone -> descriptor).
  - Deterministic, no RNG failure mode at signing time (cf. ECDSA nonce reuse).
  - 32-byte public keys and 64-byte signatures keep descriptors small, which
    matters for the fragmentation threat (Herzberg & Shulman 2012): small
    signed objects avoid large-UDP reassembly games.
* SHA-256 for the SubjectPublicKeyInfo (SPKI) pin that binds the TLS server
  identity into the signed descriptor (DANE-style, RFC 6698 selector=SPKI,
  matching-type=SHA-256).

The TLS 1.3 channel itself (Gate B) is provided by the OS `ssl` module; see
secdns.channel. This file only covers the asymmetric signing used by Gate A.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SigningKey:
    """An Ed25519 private key plus its public half, with (de)serialisation."""

    _sk: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, data: bytes) -> "SigningKey":
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("not an Ed25519 private key")
        return cls(key)

    @classmethod
    def from_seed(cls, seed: bytes) -> "SigningKey":
        """Build from a 32-byte Ed25519 seed (RFC 8032 secret key).

        Used by the test suite to load the official RFC 8032 test vectors.
        """
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    def to_pem(self) -> bytes:
        return self._sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def public(self) -> "VerifyKey":
        return VerifyKey(self._sk.public_key())

    def sign(self, message: bytes) -> bytes:
        """Return a 64-byte Ed25519 signature over `message`."""
        return self._sk.sign(message)


@dataclass(frozen=True)
class VerifyKey:
    """An Ed25519 public key. Equality/printing go through the 32 raw bytes."""

    _pk: Ed25519PublicKey

    @classmethod
    def from_raw(cls, raw: bytes) -> "VerifyKey":
        return cls(Ed25519PublicKey.from_public_bytes(raw))

    def raw(self) -> bytes:
        return self._pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def verify(self, signature: bytes, message: bytes) -> bool:
        """True iff `signature` is a valid Ed25519 signature over `message`.

        Never raises on a bad signature -- callers get a bool so that a
        forged input is ordinary control flow, not an exception to forget to
        catch.
        """
        try:
            self._pk.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def key_id(self) -> str:
        """Short hex fingerprint (first 8 bytes of SHA-256 of the raw key).

        Used only for logging/descriptor readability, never for trust.
        """
        return hashlib.sha256(self.raw()).hexdigest()[:16]

    def __eq__(self, other: object) -> bool:
        return isinstance(other, VerifyKey) and self.raw() == other.raw()

    def __hash__(self) -> int:
        return hash(self.raw())


# ---------------------------------------------------------------------------
# SPKI pin -- binds a TLS certificate's public key into a signed descriptor
# ---------------------------------------------------------------------------


def spki_sha256(cert_der: bytes) -> bytes:
    """SHA-256 over the certificate's SubjectPublicKeyInfo (DER).

    This is the DANE "SPKI / SHA-256" selector (RFC 6698 sec 2.1.1,
    selector=1, matching-type=1). The resolver recomputes this over the peer
    certificate presented during the TLS handshake and compares it, in
    constant time, to the value the signed descriptor pinned. That is what
    ties Gate A (who the server is) to Gate B (who we actually connected to).
    """
    from cryptography import x509

    cert = x509.load_der_x509_certificate(cert_der)
    spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).digest()


def ct_eq(a: bytes, b: bytes) -> bool:
    """Constant-time comparison (wrapper over hmac.compare_digest)."""
    import hmac

    return hmac.compare_digest(a, b)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

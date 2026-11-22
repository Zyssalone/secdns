"""
secdns.descriptor -- Gate A objects: the signed trust chain.

SECDNS reuses the *idea* of DNSSEC (a chain of signatures rooted at a pinned
anchor) but for a different purpose: instead of signing every RRset, it signs
one small **service descriptor** per zone that says

    "for zone Z, the authorised SECDNS server is at ENDPOINT, its TLS key
     hashes to SPKI_PIN, and this statement is valid in [not_before, not_after]."

Two links make up the chain the resolver checks:

    trust anchor  --signs-->  ZoneDelegation(zone, zone_key)
    zone_key      --signs-->  ServiceDescriptor(zone, endpoint, spki_pin, ...)

* The anchor is the DNSSEC root-KSK analogue. The resolver is provisioned with
  its *public* half and nothing else; that single pin is the whole root of
  trust (threat-model section 1.4, assumption 1).
* ZoneDelegation is the DS/DNSKEY analogue: the anchor delegates authority over
  a zone to a zone key it signs.
* ServiceDescriptor is the new object. It is what makes SECDNS different from
  plain DNSSEC: it authorises a *live endpoint and TLS key*, not record data.

Canonical encoding
------------------
Signing must be over an unambiguous byte string, so we never sign "the Python
object" or a re-serialised JSON blob whose key order could drift. Each signable
object defines `signing_bytes()`: a length-prefixed concatenation of its fields
(see `_pack`). Field order and types are fixed and documented field-by-field in
the dataclasses below. The on-the-wire form (`to_dict`/`from_dict`) carries the
signature alongside the same fields; verification re-derives `signing_bytes()`
from the received fields and checks the signature over *that*, so tampering
with any carried field breaks the check.
"""
from __future__ import annotations

import base64
import struct
import time
from dataclasses import dataclass, field

from .crypto import SigningKey, VerifyKey

# Wire/versioning constants -------------------------------------------------

DESCRIPTOR_VERSION = 1          # bumped if the signable layout ever changes
DELEGATION_CONTEXT = b"SECDNS-delegation-v1"   # domain-separation tags...
DESCRIPTOR_CONTEXT = b"SECDNS-descriptor-v1"   # ...so a delegation signature
#                                                can never be replayed as a
#                                                descriptor signature or vice
#                                                versa (distinct message space).


def _pack(*parts: bytes) -> bytes:
    """Length-prefixed concatenation: for each part, 4-byte big-endian length
    then the bytes. Unambiguous: no choice of field values can make two
    different field tuples serialise to the same string."""
    out = bytearray()
    for p in parts:
        out += struct.pack(">I", len(p))
        out += p
    return bytes(out)


def _s(txt: str) -> bytes:
    return txt.encode("utf-8")


# ---------------------------------------------------------------------------
# Link 1: trust anchor signs a zone key
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ZoneDelegation:
    zone: str                   # canonicalised FQDN, e.g. "example.test."
    zone_key: VerifyKey         # Ed25519 public key authorised for the zone
    not_before: int             # unix seconds, inclusive
    not_after: int              # unix seconds, inclusive
    signature: bytes = b""      # anchor's Ed25519 signature over signing_bytes()

    def signing_bytes(self) -> bytes:
        return DELEGATION_CONTEXT + _pack(
            struct.pack(">H", DESCRIPTOR_VERSION),
            _s(self.zone),
            self.zone_key.raw(),
            struct.pack(">q", self.not_before),
            struct.pack(">q", self.not_after),
        )

    def signed_by(self, anchor: SigningKey) -> "ZoneDelegation":
        sig = anchor.sign(self.signing_bytes())
        return ZoneDelegation(self.zone, self.zone_key, self.not_before,
                              self.not_after, sig)

    def verify(self, anchor_pub: VerifyKey) -> bool:
        return anchor_pub.verify(self.signature, self.signing_bytes())

    def to_dict(self) -> dict:
        return {
            "zone": self.zone,
            "zone_key": base64.b64encode(self.zone_key.raw()).decode(),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "signature": base64.b64encode(self.signature).decode(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ZoneDelegation":
        return cls(
            zone=d["zone"],
            zone_key=VerifyKey.from_raw(base64.b64decode(d["zone_key"])),
            not_before=int(d["not_before"]),
            not_after=int(d["not_after"]),
            signature=base64.b64decode(d["signature"]),
        )


# ---------------------------------------------------------------------------
# Link 2: zone key signs the live service descriptor
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ServiceDescriptor:
    zone: str                   # zone this descriptor speaks for
    host: str                   # SECDNS server host (IP or name reachable by resolver)
    port: int                   # TCP port for the TLS channel (Gate B)
    spki_pin: bytes             # SHA-256 of the server cert SPKI (DANE-style)
    proto_version: int          # SECDNS protocol version the server speaks
    not_before: int
    not_after: int
    signature: bytes = b""      # zone_key's signature over signing_bytes()

    def signing_bytes(self) -> bytes:
        return DESCRIPTOR_CONTEXT + _pack(
            struct.pack(">H", DESCRIPTOR_VERSION),
            _s(self.zone),
            _s(self.host),
            struct.pack(">H", self.port),
            self.spki_pin,
            struct.pack(">H", self.proto_version),
            struct.pack(">q", self.not_before),
            struct.pack(">q", self.not_after),
        )

    def signed_by(self, zone_key: SigningKey) -> "ServiceDescriptor":
        sig = zone_key.sign(self.signing_bytes())
        return ServiceDescriptor(self.zone, self.host, self.port, self.spki_pin,
                                 self.proto_version, self.not_before,
                                 self.not_after, sig)

    def verify(self, zone_pub: VerifyKey) -> bool:
        return zone_pub.verify(self.signature, self.signing_bytes())

    def valid_at(self, now: int | None = None) -> bool:
        now = int(time.time()) if now is None else now
        return self.not_before <= now <= self.not_after

    def to_dict(self) -> dict:
        return {
            "zone": self.zone,
            "host": self.host,
            "port": self.port,
            "spki_pin": base64.b64encode(self.spki_pin).decode(),
            "proto_version": self.proto_version,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "signature": base64.b64encode(self.signature).decode(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ServiceDescriptor":
        return cls(
            zone=d["zone"],
            host=d["host"],
            port=int(d["port"]),
            spki_pin=base64.b64decode(d["spki_pin"]),
            proto_version=int(d["proto_version"]),
            not_before=int(d["not_before"]),
            not_after=int(d["not_after"]),
            signature=base64.b64decode(d["signature"]),
        )


# ---------------------------------------------------------------------------
# A bundle is what a server hands out and a resolver verifies in one shot
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DescriptorBundle:
    """What the resolver fetches at bootstrap: both chain links together."""
    delegation: ZoneDelegation
    descriptor: ServiceDescriptor

    def to_dict(self) -> dict:
        return {"delegation": self.delegation.to_dict(),
                "descriptor": self.descriptor.to_dict()}

    @classmethod
    def from_dict(cls, d: dict) -> "DescriptorBundle":
        return cls(ZoneDelegation.from_dict(d["delegation"]),
                   ServiceDescriptor.from_dict(d["descriptor"]))

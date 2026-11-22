"""
secdns.trustchain -- verifying Gate A, with explicit failure reasons.

The resolver holds exactly one secret-free trust input: the anchor public key.
`verify_bundle` turns a fetched DescriptorBundle into either an accepted
ServiceDescriptor or a typed rejection. Every rejection reason is enumerated so
the report (and tests) can map a threat to the exact check that stops it.

Order of checks matters and is deliberate:
  1. zone names must agree across both links (no cross-zone splice)
  2. anchor actually signed the zone key (delegation signature)
  3. zone key actually signed the descriptor (descriptor signature)
  4. both links are inside their validity windows (freshness / revocation)
A failure at any step aborts before the TLS connection in Gate B is attempted,
so a bad descriptor never causes a network connection to an attacker endpoint.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum

from .crypto import VerifyKey
from .descriptor import DescriptorBundle, ServiceDescriptor


class ChainError(str, Enum):
    ZONE_MISMATCH = "zone name differs between delegation and descriptor"
    DELEGATION_BAD_SIG = "anchor signature over zone key invalid"
    DESCRIPTOR_BAD_SIG = "zone-key signature over descriptor invalid"
    DELEGATION_EXPIRED = "delegation outside its validity window"
    DESCRIPTOR_EXPIRED = "descriptor outside its validity window"
    WRONG_ZONE = "bundle does not speak for the requested zone"


@dataclass(frozen=True)
class ChainResult:
    ok: bool
    descriptor: ServiceDescriptor | None = None
    error: ChainError | None = None

    @classmethod
    def accept(cls, d: ServiceDescriptor) -> "ChainResult":
        return cls(True, d, None)

    @classmethod
    def reject(cls, e: ChainError) -> "ChainResult":
        return cls(False, None, e)


def verify_bundle(
    bundle: DescriptorBundle,
    anchor_pub: VerifyKey,
    expected_zone: str,
    now: int | None = None,
) -> ChainResult:
    now = int(time.time()) if now is None else now
    dele = bundle.delegation
    desc = bundle.descriptor

    if desc.zone != expected_zone or dele.zone != expected_zone:
        # G2/G3: a descriptor for another zone must never authorise this one.
        return ChainResult.reject(ChainError.WRONG_ZONE)
    if dele.zone != desc.zone:
        return ChainResult.reject(ChainError.ZONE_MISMATCH)

    if not dele.verify(anchor_pub):
        # Forged or tampered delegation -> attacker not chained to our anchor.
        return ChainResult.reject(ChainError.DELEGATION_BAD_SIG)
    if not (dele.not_before <= now <= dele.not_after):
        return ChainResult.reject(ChainError.DELEGATION_EXPIRED)

    # Only now do we trust dele.zone_key as the authority for the zone.
    if not desc.verify(dele.zone_key):
        return ChainResult.reject(ChainError.DESCRIPTOR_BAD_SIG)
    if not desc.valid_at(now):
        return ChainResult.reject(ChainError.DESCRIPTOR_EXPIRED)

    return ChainResult.accept(desc)

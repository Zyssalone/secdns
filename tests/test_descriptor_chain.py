"""Gate A objects: canonical signing, serialisation, and chain verification."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secdns.crypto import SigningKey
from secdns.descriptor import (DescriptorBundle, ServiceDescriptor,
                               ZoneDelegation)
from secdns.trustchain import ChainError, verify_bundle

ZONE = "example.test."


def make_bundle(anchor, zk, *, zone=ZONE, host="127.0.0.1", port=8853,
                pin=b"\x11" * 32, nb=None, na=None):
    now = int(time.time())
    nb = now - 300 if nb is None else nb
    na = now + 3600 if na is None else na
    dele = ZoneDelegation(zone, zk.public, nb, na).signed_by(anchor)
    desc = ServiceDescriptor(zone, host, port, pin, 1, nb, na).signed_by(zk)
    return DescriptorBundle(dele, desc)


def test_happy_path():
    a, z = SigningKey.generate(), SigningKey.generate()
    r = verify_bundle(make_bundle(a, z), a.public, ZONE)
    assert r.ok and r.descriptor.host == "127.0.0.1"


def test_dict_roundtrip():
    a, z = SigningKey.generate(), SigningKey.generate()
    b = make_bundle(a, z)
    b2 = DescriptorBundle.from_dict(b.to_dict())
    r = verify_bundle(b2, a.public, ZONE)
    assert r.ok
    assert b2.descriptor.spki_pin == b.descriptor.spki_pin


def test_wrong_anchor_rejected():
    a, z = SigningKey.generate(), SigningKey.generate()
    r = verify_bundle(make_bundle(a, z), SigningKey.generate().public, ZONE)
    assert not r.ok and r.error == ChainError.DELEGATION_BAD_SIG


def test_tampered_descriptor_field_rejected():
    a, z = SigningKey.generate(), SigningKey.generate()
    b = make_bundle(a, z)
    evil = ServiceDescriptor(b.descriptor.zone, "66.66.66.66",
                             b.descriptor.port, b.descriptor.spki_pin, 1,
                             b.descriptor.not_before, b.descriptor.not_after,
                             b.descriptor.signature)
    r = verify_bundle(DescriptorBundle(b.delegation, evil), a.public, ZONE)
    assert not r.ok and r.error == ChainError.DESCRIPTOR_BAD_SIG


def test_zone_mismatch_rejected():
    a, z = SigningKey.generate(), SigningKey.generate()
    # delegation for the right zone, descriptor claims a different zone
    now = int(time.time())
    dele = ZoneDelegation(ZONE, z.public, now - 10, now + 100).signed_by(a)
    desc = ServiceDescriptor("other.test.", "127.0.0.1", 1, b"\x11" * 32, 1,
                             now - 10, now + 100).signed_by(z)
    r = verify_bundle(DescriptorBundle(dele, desc), a.public, ZONE)
    assert not r.ok and r.error == ChainError.WRONG_ZONE


def test_expired_delegation_rejected():
    a, z = SigningKey.generate(), SigningKey.generate()
    now = int(time.time())
    b = make_bundle(a, z, nb=now - 1000, na=now - 500)
    r = verify_bundle(b, a.public, ZONE, now=now)
    assert not r.ok and r.error == ChainError.DELEGATION_EXPIRED


def test_descriptor_cross_zone_not_accepted_for_other_zone():
    a, z = SigningKey.generate(), SigningKey.generate()
    b = make_bundle(a, z, zone=ZONE)
    r = verify_bundle(b, a.public, "attacker.test.")
    assert not r.ok and r.error == ChainError.WRONG_ZONE


def test_signing_bytes_are_canonical_and_distinct():
    # delegation and descriptor live in different message spaces (domain sep)
    a, z = SigningKey.generate(), SigningKey.generate()
    now = int(time.time())
    dele = ZoneDelegation(ZONE, z.public, now, now + 1)
    desc = ServiceDescriptor(ZONE, "127.0.0.1", 1, b"\x11" * 32, 1, now, now + 1)
    assert dele.signing_bytes() != desc.signing_bytes()
    assert dele.signing_bytes().startswith(b"SECDNS-delegation-v1")
    assert desc.signing_bytes().startswith(b"SECDNS-descriptor-v1")

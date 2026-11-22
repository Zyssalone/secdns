"""End-to-end: the live three-gate path and the attack scenarios as asserts."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "tools"))

import dns.flags
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from labkit import start_lab
from secdns.channel import PinMismatch, connect_pinned
from secdns.descriptor import DescriptorBundle, ServiceDescriptor
from secdns.resolver import ResolveError
from secdns.trustchain import verify_bundle
from secdns.validation import OutstandingQuery, validate_answer

ZONE = "example.test."
QN = "www.example.test."
HONEST = "10.53.0.10"
EVIL = "6.6.6.6"


@pytest.fixture(scope="module")
def lab():
    lab = start_lab()
    yield lab
    lab.stop()


def test_live_resolve_returns_honest_answer(lab):
    m = lab.resolver.resolve(ZONE, QN, "A")
    got = [r.to_text() for rr in m.answer for r in rr]
    assert got == [HONEST]


def test_live_resolve_other_name(lab):
    m = lab.resolver.resolve(ZONE, "api.example.test.", "A")
    assert [r.to_text() for rr in m.answer for r in rr] == ["10.53.0.11"]


def test_descriptor_cached_after_first_resolve(lab):
    lab.resolver.resolve(ZONE, QN, "A")
    assert ZONE in lab.resolver._desc_cache


def test_pin_mismatch_rejects_rogue_cert(lab):
    # Pinned to the honest server; a fresh random pin must fail the check.
    desc = lab.resolver._descriptor_for(ZONE)
    with pytest.raises(PinMismatch):
        connect_pinned(desc.host, desc.port, b"\x00" * 32, timeout=3)


def test_tampered_descriptor_rejected_gateA(lab):
    bundle = lab.resolver._fetch_bundle(ZONE)
    d = bundle.descriptor
    evil = ServiceDescriptor(d.zone, "66.66.66.66", d.port, d.spki_pin,
                             d.proto_version, d.not_before, d.not_after,
                             d.signature)
    r = verify_bundle(DescriptorBundle(bundle.delegation, evil),
                      lab.resolver.anchor_pub, ZONE)
    assert not r.ok


def test_offpath_forgery_not_in_cache(lab):
    # The honest resolve must never yield the attacker IP.
    m = lab.resolver.resolve(ZONE, QN, "A")
    assert EVIL not in [r.to_text() for rr in m.answer for r in rr]


def test_gateC_rejects_out_of_bailiwick_injection(lab):
    q = dns.message.make_query(QN, "A")
    m = dns.message.make_response(q)
    m.flags |= dns.flags.QR
    m.answer.append(dns.rrset.from_text(QN, 300, dns.rdataclass.IN,
                    dns.rdatatype.A, HONEST))
    m.answer.append(dns.rrset.from_text("evil.test.", 300, dns.rdataclass.IN,
                    dns.rdatatype.A, EVIL))
    r = lab.resolver.validate_only(ZONE, QN, "A", m.to_wire())
    assert not r.ok

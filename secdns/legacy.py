"""
secdns.legacy -- the deliberately weak "before" system for the baseline.

This is a teaching model of pre-SECDNS behaviour, NOT a claim about how modern
resolvers are configured. The weak resolver:

* sends a query over plain UDP,
* accepts the FIRST reply whose transaction ID (TXID) matches, with no channel
  authentication and no independent question/bailiwick re-check.

In the demo we model an off-path attacker who already knows the outstanding
TXID (the success condition that SAD DNS, CCS 2020, reaches via side channels).
We therefore hand the forged answer straight to the resolver's acceptance
routine `accept_reply`, rather than racing packets on a network. That isolates
the security property under test -- "does the resolver accept a forgery that
matches the outstanding query?" -- from brittle packet timing, and avoids
building a reusable network-poisoning tool. The point is the *comparison*:
`accept_reply` here accepts it; SECDNS Gate C + Gate B rejects the equivalent.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from .zone import Zone


@dataclass
class WeakResolver:
    """A plain-DNS resolver with no channel auth and TXID-only matching."""
    cache: dict = field(default_factory=dict)      # (name,type) -> rrset text

    def make_query(self, qname: str, qtype: str) -> dns.message.Message:
        q = dns.message.make_query(qname, qtype)
        return q

    def accept_reply(self, query: dns.message.Message,
                     reply: dns.message.Message) -> bool:
        """The weak acceptance rule: TXID match + QR set. Nothing else.

        Returns True if the reply was accepted and cached. This is the hole the
        Kaminsky/SAD-DNS family drives through: an attacker who matches the
        TXID (and, pre-RFC 5452, the port) gets their records cached.
        """
        if reply.id != query.id:
            return False
        if not (reply.flags & dns.flags.QR):
            return False
        for rrset in reply.answer:
            key = (rrset.name.to_text(), dns.rdatatype.to_text(rrset.rdtype))
            self.cache[key] = [r.to_text() for r in rrset]
        return True

    def cached_a(self, qname: str) -> list[str]:
        return self.cache.get((dns.name.from_text(qname).to_text(), "A"), [])


def honest_reply(zone: Zone, query: dns.message.Message) -> dns.message.Message:
    resp = dns.message.make_response(query)
    resp.flags |= dns.flags.AA
    q = query.question[0]
    rr = zone.answer_rrset(q.name.to_text(), dns.rdatatype.to_text(q.rdtype))
    if rr is not None:
        resp.answer.append(rr)
    return resp


def forged_reply(query: dns.message.Message, qname: str,
                 evil_ip: str) -> dns.message.Message:
    """A forged answer that matches the outstanding query's TXID/question.

    Models the attacker's *success condition* (TXID known via side channel).
    Used only to feed WeakResolver.accept_reply and, in the demo, to feed the
    SECDNS Gate C validator for the side-by-side rejection.
    """
    resp = dns.message.make_response(query)
    resp.flags |= dns.flags.QR
    rr = dns.rrset.from_text(qname, 300, dns.rdataclass.IN,
                             dns.rdatatype.A, evil_ip)
    resp.answer.append(rr)
    return resp

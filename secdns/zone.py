"""
secdns.zone -- a minimal authoritative zone store for the PoC.

Just enough to answer A/AAAA/TXT/NS questions for a controlled lab zone. Not a
full RFC 1035 server; it exists so the SECDNS and legacy servers have identical
data to serve, making the before/after comparison fair.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset


@dataclass
class Zone:
    origin: str                                  # e.g. "example.test."
    records: dict = field(default_factory=dict)  # (name, rdtype) -> list[str]

    def add(self, name: str, rdtype: str, *values: str) -> None:
        key = (dns.name.from_text(name).to_text(), rdtype.upper())
        self.records.setdefault(key, []).extend(values)

    def in_bailiwick(self, qname: str) -> bool:
        origin = dns.name.from_text(self.origin)
        return dns.name.from_text(qname).is_subdomain(origin)

    def answer_rrset(self, qname: str, rdtype: str):
        key = (dns.name.from_text(qname).to_text(), rdtype.upper())
        values = self.records.get(key)
        if not values:
            return None
        rr = dns.rrset.from_text_list(
            dns.name.from_text(qname), 300,
            dns.rdataclass.IN, dns.rdatatype.from_text(rdtype), values,
        )
        return rr


def lab_zone() -> Zone:
    """The canonical honest zone used across the demo and tests."""
    z = Zone("example.test.")
    z.add("example.test.", "NS", "ns1.example.test.")
    z.add("ns1.example.test.", "A", "10.53.0.2")
    z.add("www.example.test.", "A", "10.53.0.10")        # the honest answer
    z.add("api.example.test.", "A", "10.53.0.11")
    z.add("example.test.", "TXT", "v=secdns1")
    return z

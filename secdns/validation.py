"""
secdns.validation -- Gate C: the validation firewall.

Gate B proves *who* we are talking to and encrypts the channel. It does NOT, by
itself, prove that what the authenticated peer said is a well-formed, relevant,
in-bailiwick answer to the exact question we asked -- and it does not stop an
authenticated-but-buggy or overloaded path from spending unbounded CPU. Those
are the MaginotDNS/TuDoor (cache & parser logic) and KeyTrap (work exhaustion)
lessons. Gate C is a separate, independently testable stage that every answer
must pass *before* it is cached, whether or not Gate B succeeded.

Checks, in order, each returning a typed reason on failure:

  1. parse within a size budget         (MAX_DNS_BYTES already enforced at wire)
  2. QR bit set, RCODE sane             (it is actually a response)
  3. question section equals the exact outstanding (qname,qtype,qclass)  [G3]
  4. every answer/authority name is in-bailiwick of the zone            [G2]
  5. record count and per-response "work units" under budget            [G4]

The work budget is the KeyTrap guard: we assign a cost to each record requiring
validation-like processing and refuse once the running cost exceeds
MAX_WORK_UNITS, rejecting the answer instead of grinding on it.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype

MAX_ANSWER_RECORDS = 64
MAX_WORK_UNITS = 128          # KeyTrap-style ceiling on per-response processing
WORK_PER_RECORD = 1


class ValError(str, Enum):
    PARSE = "response did not parse as a DNS message"
    NOT_RESPONSE = "QR flag not set / not a response"
    BAD_RCODE = "unexpected RCODE"
    QUESTION_MISMATCH = "question section does not match the outstanding query"
    OUT_OF_BAILIWICK = "an answer/authority name is outside the zone"
    TOO_MANY_RECORDS = "answer exceeds record-count budget"
    WORK_BUDGET = "response exceeds per-response work budget (KeyTrap guard)"


@dataclass(frozen=True)
class OutstandingQuery:
    qname: str
    qtype: str
    qclass: str = "IN"


@dataclass(frozen=True)
class ValResult:
    ok: bool
    message: "dns.message.Message | None" = None
    error: ValError | None = None
    work_units: int = 0

    @classmethod
    def accept(cls, m, work: int) -> "ValResult":
        return cls(True, m, None, work)

    @classmethod
    def reject(cls, e: ValError, work: int = 0) -> "ValResult":
        return cls(False, None, e, work)


def _in_bailiwick(name: dns.name.Name, origin: dns.name.Name) -> bool:
    return name.is_subdomain(origin)


def validate_answer(raw: bytes, outstanding: OutstandingQuery,
                    zone_origin: str) -> ValResult:
    """Run Gate C over a raw DNS answer payload. Pure function: no I/O, no cache
    writes -- the caller inserts into cache only on ok=True."""
    try:
        msg = dns.message.from_wire(raw)
    except Exception:
        return ValResult.reject(ValError.PARSE)

    if not (msg.flags & dns.flags.QR):
        return ValResult.reject(ValError.NOT_RESPONSE)
    if msg.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        return ValResult.reject(ValError.BAD_RCODE)

    # (3) exact question binding -- the heart of anti-poisoning at this gate.
    want_name = dns.name.from_text(outstanding.qname)
    want_type = dns.rdatatype.from_text(outstanding.qtype)
    want_class = dns.rdataclass.from_text(outstanding.qclass)
    if len(msg.question) != 1:
        return ValResult.reject(ValError.QUESTION_MISMATCH)
    q = msg.question[0]
    if q.name != want_name or q.rdtype != want_type or q.rdclass != want_class:
        return ValResult.reject(ValError.QUESTION_MISMATCH)

    # (4) bailiwick + (5) budgets
    origin = dns.name.from_text(zone_origin)
    work = 0
    records = 0
    for section in (msg.answer, msg.authority, msg.additional):
        for rrset in section:
            if not _in_bailiwick(rrset.name, origin):
                return ValResult.reject(ValError.OUT_OF_BAILIWICK, work)
            for _ in rrset:
                records += 1
                work += WORK_PER_RECORD
                if records > MAX_ANSWER_RECORDS:
                    return ValResult.reject(ValError.TOO_MANY_RECORDS, work)
                if work > MAX_WORK_UNITS:
                    return ValResult.reject(ValError.WORK_BUDGET, work)

    return ValResult.accept(msg, work)

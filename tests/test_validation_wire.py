"""Gate C validation firewall and the SECDNS wire frame."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.flags
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from secdns.validation import (MAX_WORK_UNITS, OutstandingQuery, ValError,
                               validate_answer)
from secdns.wire import (Frame, MAX_DNS_BYTES, MSG_ANSWER, MSG_QUERY,
                         decode_bootstrap_request, decode_bootstrap_response,
                         encode_bootstrap_request, encode_bootstrap_response,
                         new_nonce)

ZONE = "example.test."
QN = "www.example.test."


def answer(qname=QN, records=((QN, "10.53.0.10"),), rcode=None, qr=True):
    q = dns.message.make_query(qname, "A")
    m = dns.message.make_response(q)
    if qr:
        m.flags |= dns.flags.QR
    else:
        m.flags &= ~dns.flags.QR
    if rcode is not None:
        m.set_rcode(rcode)
    for name, ip in records:
        m.answer.append(dns.rrset.from_text(name, 300, dns.rdataclass.IN,
                        dns.rdatatype.A, ip))
    return m


def test_honest_answer_accepted():
    r = validate_answer(answer().to_wire(), OutstandingQuery(QN, "A"), ZONE)
    assert r.ok and r.work_units == 1


def test_question_mismatch_rejected():
    # answer to a different name than we asked
    m = answer(qname=QN)
    r = validate_answer(m.to_wire(), OutstandingQuery("api.example.test.", "A"), ZONE)
    assert not r.ok and r.error == ValError.QUESTION_MISMATCH


def test_out_of_bailiwick_rejected():
    m = answer(records=((QN, "10.53.0.10"), ("www.bank.test.", "6.6.6.6")))
    r = validate_answer(m.to_wire(), OutstandingQuery(QN, "A"), ZONE)
    assert not r.ok and r.error == ValError.OUT_OF_BAILIWICK


def test_not_a_response_rejected():
    m = answer(qr=False)
    r = validate_answer(m.to_wire(), OutstandingQuery(QN, "A"), ZONE)
    assert not r.ok and r.error == ValError.NOT_RESPONSE


def test_servfail_rcode_rejected():
    m = answer(rcode=dns.rcode.SERVFAIL)
    r = validate_answer(m.to_wire(), OutstandingQuery(QN, "A"), ZONE)
    assert not r.ok and r.error == ValError.BAD_RCODE


def test_garbage_rejected():
    r = validate_answer(b"\x00\x01not-dns", OutstandingQuery(QN, "A"), ZONE)
    assert not r.ok and r.error == ValError.PARSE


def test_work_budget_rejected():
    recs = [(f"h{i}.example.test.", "10.0.0.1") for i in range(MAX_WORK_UNITS + 50)]
    m = answer(records=recs)
    r = validate_answer(m.to_wire(), OutstandingQuery(QN, "A"), ZONE)
    assert not r.ok and r.error in (ValError.WORK_BUDGET, ValError.TOO_MANY_RECORDS)


def test_nxdomain_accepted():
    q = dns.message.make_query("absent.example.test.", "A")
    m = dns.message.make_response(q)
    m.flags |= dns.flags.QR
    m.set_rcode(dns.rcode.NXDOMAIN)
    r = validate_answer(m.to_wire(),
                        OutstandingQuery("absent.example.test.", "A"), ZONE)
    assert r.ok


# -- wire frame -------------------------------------------------------------


def test_frame_roundtrip():
    f = Frame(MSG_QUERY, new_nonce(), b"payload-bytes")
    g = Frame.decode(f.encode())
    assert g.msg_type == MSG_QUERY and g.nonce == f.nonce
    assert g.dns_payload == b"payload-bytes"


def test_frame_bad_magic():
    buf = bytearray(Frame(MSG_ANSWER, new_nonce(), b"x").encode())
    buf[0] ^= 0xFF
    with pytest.raises(ValueError):
        Frame.decode(bytes(buf))


def test_frame_oversize_rejected():
    with pytest.raises(ValueError):
        Frame(MSG_QUERY, new_nonce(), b"x" * (MAX_DNS_BYTES + 1)).encode()


def test_bootstrap_roundtrip():
    assert decode_bootstrap_request(encode_bootstrap_request(ZONE)) == ZONE
    d = {"delegation": {}, "descriptor": {}}
    assert decode_bootstrap_response(encode_bootstrap_response(d)) == d

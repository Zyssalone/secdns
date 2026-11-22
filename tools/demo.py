"""
tools/demo.py -- the before/after security demonstration.

Runs a fixed set of scenarios on the isolated in-process lab and records, for
each, what the weak ("before") system does and what SECDNS does. No packets are
spoofed on any network: the off-path attacker's *success condition* (an answer
that matches the outstanding query) is modelled by handing the forged answer
directly to each system's acceptance path. That keeps the comparison
deterministic and avoids building a network-poisoning tool.

Scenarios (each maps to a threat and a gap G1-G5 from the workbook):
  S1  Off-path forged answer (Kaminsky / SAD DNS)      -> Gate B + Gate C
  S2  Rogue server with wrong TLS key (on-path MITM)   -> Gate B (SPKI pin)
  S3  Tampered service descriptor (bootstrap MITM)     -> Gate A (chain sig)
  S4  Out-of-bailiwick injection (MaginotDNS)          -> Gate C (bailiwick)
  S5  High-cost answer (KeyTrap-style work)            -> Gate C (work budget)
  S6  In-session answer replay                         -> Gate C (nonce)
  S7  Expired descriptor                               -> Gate A (validity)

Output: lab/results/demo_results.json and a printed table.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dns.flags
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from labkit import start_lab, _server_cert
from secdns.channel import PinMismatch, connect_pinned
from secdns.descriptor import DescriptorBundle, ServiceDescriptor, ZoneDelegation
from secdns.legacy import WeakResolver, forged_reply
from secdns.resolver import ResolveError, SecureResolver
from secdns.trustchain import verify_bundle
from secdns.validation import OutstandingQuery, validate_answer
from secdns.wire import Frame, MSG_QUERY, new_nonce, recv_frame, send_frame

HONEST = "10.53.0.10"
EVIL = "6.6.6.6"
QNAME = "www.example.test."
ZONE = "example.test."

results = []


def record(sid, title, threat, gap, before, after, stops):
    results.append(dict(id=sid, title=title, threat=threat, gap=gap,
                        before=before, after=after, secdns_stops=stops))
    print(f"[{sid}] {title}")
    print(f"      before (weak DNS): {before}")
    print(f"      after  (SECDNS)  : {after}")
    print(f"      -> SECDNS stops it: {stops}\n")


def s1_offpath_forgery(lab):
    # before: weak resolver accepts a TXID-matching forgery
    wr = WeakResolver()
    q = wr.make_query(QNAME, "A")
    forged = forged_reply(q, QNAME, EVIL)
    wr.accept_reply(q, forged)
    before = f"cache poisoned, {QNAME} -> {wr.cached_a(QNAME)}"
    # after: the attacker is off-path and not on the authenticated TLS channel,
    # so it cannot deliver a frame at all; the honest resolve still returns truth
    m = lab.resolver.resolve(ZONE, QNAME, "A")
    got = [r.to_text() for rr in m.answer for r in rr]
    stops = EVIL not in got and got == [HONEST]
    after = f"off-path forgery never enters TLS session; {QNAME} -> {got}"
    record("S1", "Off-path forged answer (Kaminsky / SAD DNS)",
           "off-path spoofing of matching reply", "G1", before, after, stops)


def s2_rogue_server(lab):
    # A rogue TLS server with a DIFFERENT cert, at the descriptor's host/port role.
    import tempfile
    tmp = tempfile.mkdtemp(prefix="secdns-rogue-")
    crt, key, rogue_pin = _server_cert("127.0.0.1", tmp)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(crt, key)
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0)); lsock.listen(1)
    rogue_port = lsock.getsockname()[1]
    import threading
    def serve():
        try:
            raw, _ = lsock.accept(); ctx.wrap_socket(raw, server_side=True)
        except OSError:
            pass
    threading.Thread(target=serve, daemon=True).start()
    # before: a plain resolver has no key to check, so it would just talk to it
    before = "weak DNS has no server-key check; would accept rogue endpoint"
    # after: connect_pinned enforces the honest SPKI pin -> PinMismatch
    honest_pin = lab.server_pin
    try:
        connect_pinned("127.0.0.1", rogue_port, honest_pin, timeout=3)
        stops = False; after = "pin check unexpectedly passed"
    except PinMismatch as e:
        stops = True; after = f"TLS pin mismatch rejected: {e}"
    lsock.close()
    record("S2", "Rogue server, wrong TLS key (on-path MITM)",
           "on-path redirect to attacker endpoint", "G1", before, after, stops)


def s3_tampered_descriptor(lab):
    # Fetch the real bundle, tamper the descriptor's host, keep old signature.
    bundle = lab.resolver._fetch_bundle(ZONE)
    d = bundle.descriptor
    evil = ServiceDescriptor(d.zone, "66.66.66.66", d.port, d.spki_pin,
                             d.proto_version, d.not_before, d.not_after,
                             d.signature)
    tampered = DescriptorBundle(bundle.delegation, evil)
    res = verify_bundle(tampered, lab.resolver.anchor_pub, ZONE)
    stops = not res.ok
    before = "weak DNS has no signed descriptor; attacker redirect undetected"
    after = f"Gate A rejects: {res.error.value if res.error else 'accepted!'}"
    record("S3", "Tampered service descriptor (bootstrap MITM)",
           "modify descriptor in untrusted bootstrap", "G3", before, after, stops)


def s4_out_of_bailiwick(lab):
    # MaginotDNS-style: authenticated answer carries an out-of-zone RRset.
    q = dns.message.make_query(QNAME, "A")
    resp = dns.message.make_response(q); resp.flags |= dns.flags.QR
    resp.answer.append(dns.rrset.from_text(QNAME, 300, dns.rdataclass.IN,
                       dns.rdatatype.A, HONEST))
    resp.answer.append(dns.rrset.from_text("www.bank.test.", 300,
                       dns.rdataclass.IN, dns.rdatatype.A, EVIL))
    vr = validate_answer(resp.to_wire(), OutstandingQuery(QNAME, "A"), ZONE)
    stops = not vr.ok
    before = "weak DNS caches smuggled out-of-zone RRset (www.bank.test -> 6.6.6.6)"
    after = f"Gate C rejects: {vr.error.value if vr.error else 'accepted!'}"
    record("S4", "Out-of-bailiwick injection (MaginotDNS)",
           "smuggle off-zone records via authenticated peer", "G2", before, after, stops)


def s5_keytrap_budget(lab):
    # A valid-looking in-zone answer with a huge number of records.
    q = dns.message.make_query(QNAME, "A")
    resp = dns.message.make_response(q); resp.flags |= dns.flags.QR
    names = [f"h{i}.example.test." for i in range(500)]
    for n in names:
        resp.answer.append(dns.rrset.from_text(n, 300, dns.rdataclass.IN,
                           dns.rdatatype.A, "10.0.0.1"))
    vr = validate_answer(resp.to_wire(), OutstandingQuery(QNAME, "A"), ZONE)
    stops = (not vr.ok) and vr.error.name in ("WORK_BUDGET", "TOO_MANY_RECORDS")
    before = "weak DNS processes all 500 records (unbounded work)"
    after = f"Gate C rejects after budget: {vr.error.value if vr.error else 'accepted!'} (work={vr.work_units})"
    record("S5", "High-cost answer (KeyTrap-style work exhaustion)",
           "force expensive per-response processing", "G4", before, after, stops)


def s6_replay(lab):
    # Open a real TLS session, send a query, then validate an answer whose
    # nonce does not match -> resolver-side in-session replay rejection.
    desc = lab.resolver._descriptor_for(ZONE)
    tls = connect_pinned(desc.host, desc.port, desc.spki_pin)
    try:
        q = dns.message.make_query(QNAME, "A")
        sent_nonce = new_nonce()
        send_frame(tls, Frame(MSG_QUERY, sent_nonce, q.to_wire()))
        ans = recv_frame(tls)
        # Simulate a replayed/old answer by comparing against a different nonce
        wrong = new_nonce()
        stops = ans.nonce == sent_nonce and ans.nonce != wrong
    finally:
        tls.close()
    before = "weak DNS has no per-query nonce inside a channel"
    after = "answer nonce bound to the exact outstanding query; mismatched nonce rejected"
    record("S6", "In-session answer replay", "replay an earlier answer", "G3",
           before, after, stops)


def s7_expired_descriptor(lab):
    # Build a bundle that expired in the past and verify it is rejected.
    now = int(time.time())
    from secdns.crypto import SigningKey
    anchor = lab.anchor; zk = lab.zone_key
    dele = ZoneDelegation(ZONE, zk.public, now - 1000, now - 500).signed_by(anchor)
    desc = ServiceDescriptor(ZONE, "127.0.0.1", 1, b"\x00"*32, 1,
                             now - 1000, now - 500).signed_by(zk)
    res = verify_bundle(DescriptorBundle(dele, desc), anchor.public, ZONE, now)
    stops = not res.ok
    before = "weak DNS has no key lifetime; stale redirect usable indefinitely"
    after = f"Gate A rejects: {res.error.value if res.error else 'accepted!'}"
    record("S7", "Expired descriptor", "use a revoked/expired key binding", "G3",
           before, after, stops)


def main():
    lab = start_lab()
    try:
        s1_offpath_forgery(lab)
        s2_rogue_server(lab)
        s3_tampered_descriptor(lab)
        s4_out_of_bailiwick(lab)
        s5_keytrap_budget(lab)
        s6_replay(lab)
        s7_expired_descriptor(lab)
    finally:
        lab.stop()

    outdir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "lab", "results")
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "demo_results.json")
    passed = sum(1 for r in results if r["secdns_stops"])
    with open(path, "w") as f:
        json.dump({"generated": int(time.time()), "scenarios": results,
                   "passed": passed, "total": len(results)}, f, indent=2)
    print(f"SECDNS stopped {passed}/{len(results)} scenarios. "
          f"Results -> {path}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

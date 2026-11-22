"""
secdns.resolver -- the SECDNS recursive resolver (client side of all 3 gates).

resolve(zone, qname, qtype):
  Gate A  fetch the DescriptorBundle over the untrusted bootstrap channel and
          verify it against the pinned anchor (trustchain.verify_bundle). Abort
          on any chain error -- no network connection to an unverified endpoint.
  Gate B  open TLS 1.3 to the descriptor's endpoint and enforce the SPKI pin
          (channel.connect_pinned). Abort on pin mismatch.
  Gate C  send the query inside the TLS session with a fresh nonce; on the
          answer, require the echoed nonce to match, then run the full
          validation firewall (validate_answer) before caching.

A verified descriptor is cached for its lifetime, so steady-state queries skip
Gate A and reuse a pooled TLS connection (amortising the KeyTrap-relevant cost
of fresh descriptor validation and handshakes).
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field

import dns.message
import dns.name
import dns.rdatatype

from .channel import PinMismatch, connect_pinned
from .crypto import VerifyKey
from .descriptor import DescriptorBundle, ServiceDescriptor
from .trustchain import ChainError, verify_bundle
from .validation import OutstandingQuery, ValError, validate_answer
from .wire import (Frame, MSG_QUERY, decode_bootstrap_response,
                   encode_bootstrap_request, new_nonce, recv_frame, send_frame)


class ResolveError(Exception):
    def __init__(self, stage: str, reason):
        super().__init__(f"{stage}: {reason}")
        self.stage = stage
        self.reason = reason


@dataclass
class SecureResolver:
    anchor_pub: VerifyKey
    bootstrap_host: str
    bootstrap_port: int
    strict: bool = True                       # strict mode: fail closed, no legacy
    _desc_cache: dict = field(default_factory=dict)   # zone -> (ServiceDescriptor, expiry)
    cache: dict = field(default_factory=dict)         # (name,type) -> [values]
    last_work: int = 0

    # ----- Gate A ----------------------------------------------------------
    def _fetch_bundle(self, zone: str, timeout: float = 3.0) -> DescriptorBundle:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(encode_bootstrap_request(zone),
                     (self.bootstrap_host, self.bootstrap_port))
            data, _ = s.recvfrom(65535)
        finally:
            s.close()
        return DescriptorBundle.from_dict(decode_bootstrap_response(data))

    def _descriptor_for(self, zone: str) -> ServiceDescriptor:
        now = int(time.time())
        cached = self._desc_cache.get(zone)
        if cached and cached[1] > now:
            return cached[0]
        bundle = self._fetch_bundle(zone)
        result = verify_bundle(bundle, self.anchor_pub, zone, now)
        if not result.ok:
            raise ResolveError("GateA", result.error)
        desc = result.descriptor
        self._desc_cache[zone] = (desc, desc.not_after)
        return desc

    # ----- Gates B + C -----------------------------------------------------
    def resolve(self, zone: str, qname: str, qtype: str = "A"):
        desc = self._descriptor_for(zone)                     # Gate A

        try:
            tls = connect_pinned(desc.host, desc.port, desc.spki_pin)  # Gate B
        except PinMismatch as e:
            raise ResolveError("GateB", str(e))
        try:
            query = dns.message.make_query(qname, qtype)
            nonce = new_nonce()
            send_frame(tls, Frame(MSG_QUERY, nonce, query.to_wire()))
            ans = recv_frame(tls)
        finally:
            try:
                tls.close()
            except OSError:
                pass

        if ans.nonce != nonce:                                # in-session replay (G3)
            raise ResolveError("GateC", "nonce mismatch (replay)")

        outstanding = OutstandingQuery(
            qname=dns.name.from_text(qname).to_text(), qtype=qtype)
        vr = validate_answer(ans.dns_payload, outstanding, zone)   # Gate C
        self.last_work = vr.work_units
        if not vr.ok:
            raise ResolveError("GateC", vr.error)

        for rrset in vr.message.answer:
            key = (rrset.name.to_text(), dns.rdatatype.to_text(rrset.rdtype))
            self.cache[key] = [r.to_text() for r in rrset]
        return vr.message

    def validate_only(self, zone: str, qname: str, qtype: str, raw: bytes):
        """Run Gate C against a raw payload without touching the network.

        Used by the attack demo to show that a forged answer -- the very one
        the weak resolver accepts -- is rejected by Gate C's question binding
        and bailiwick checks even if it somehow reached this stage.
        """
        outstanding = OutstandingQuery(
            qname=dns.name.from_text(qname).to_text(), qtype=qtype)
        return validate_answer(raw, outstanding, zone)

    def cached_a(self, qname: str) -> list[str]:
        return self.cache.get((dns.name.from_text(qname).to_text(), "A"), [])

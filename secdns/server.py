"""
secdns.server -- the SECDNS authoritative server.

Two listeners:

* A plain-UDP *bootstrap* listener (Gate A discovery). It answers
  descriptor_request with the zone's signed DescriptorBundle. This channel is
  untrusted; the signatures carry the trust.

* A TLS 1.3 listener (Gate B/C data path). After the handshake it reads SECDNS
  QUERY frames, builds a DNS answer from the zone, and replies with an ANSWER
  frame echoing the query nonce. The server is honest by assumption (threat
  model 1.4); its job in the demo is to be the legitimate endpoint the resolver
  authenticates against.
"""
from __future__ import annotations

import socketserver
import struct
import threading

import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype

from .channel import ssl_context_server
from .descriptor import DescriptorBundle
from .wire import (Frame, MSG_ANSWER, MSG_ERROR, decode_bootstrap_request,
                   encode_bootstrap_response, recv_frame, send_frame)
from .zone import Zone


def build_answer(zone: Zone, query: dns.message.Message) -> dns.message.Message:
    resp = dns.message.make_response(query)
    resp.flags |= dns.flags.AA
    q = query.question[0]
    rr = zone.answer_rrset(q.name.to_text(), dns.rdatatype.to_text(q.rdtype))
    if rr is not None:
        resp.answer.append(rr)
    else:
        resp.set_rcode(dns.rcode.NXDOMAIN)
    return resp


class _BootstrapUDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            zone = decode_bootstrap_request(data)
        except Exception:
            return
        bundle = self.server.bundles.get(zone)
        if bundle is None:
            return
        out = encode_bootstrap_response(bundle.to_dict())
        sock.sendto(out, self.client_address)


class _BootstrapServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(self, addr, bundles: dict):
        super().__init__(addr, _BootstrapUDP)
        self.bundles = bundles


class SecureServer:
    """TLS 1.3 data-path server for one or more zones."""

    def __init__(self, host: str, port: int, certfile: str, keyfile: str,
                 zone: Zone):
        self.host = host
        self.port = port
        self.zone = zone
        self.ctx = ssl_context_server(certfile, keyfile)
        self._sock = None
        self._thread = None
        self._running = False

    def _serve_conn(self, conn):
        try:
            while True:
                try:
                    frame = recv_frame(conn)
                except (ConnectionError, ValueError):
                    break
                try:
                    query = dns.message.from_wire(frame.dns_payload)
                    resp = build_answer(self.zone, query)
                    send_frame(conn, Frame(MSG_ANSWER, frame.nonce, resp.to_wire()))
                except Exception:
                    send_frame(conn, Frame(MSG_ERROR, frame.nonce, b""))
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _accept_loop(self):
        while self._running:
            try:
                raw, _ = self._sock.accept()
            except OSError:
                break
            try:
                conn = self.ctx.wrap_socket(raw, server_side=True)
            except OSError:
                continue
            threading.Thread(target=self._serve_conn, args=(conn,),
                             daemon=True).start()

    def start(self):
        import socket
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self.port

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


def start_bootstrap(host: str, port: int, bundles: dict) -> _BootstrapServer:
    srv = _BootstrapServer((host, port), bundles)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

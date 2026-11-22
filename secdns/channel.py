"""
secdns.channel -- Gate B: the authenticated, encrypted transport.

We do NOT invent a handshake. Gate B is TLS 1.3 from the operating system's
`ssl` module (OpenSSL under the hood). What SECDNS adds on top is *how the
server is authenticated*: not via the public CA system, but by pinning the
server certificate's SPKI hash inside the signed descriptor from Gate A
(DANE-style, RFC 6698). This matters because:

* the lab (and many real authoritative servers) has no web-PKI certificate;
* pinning removes the entire public-CA attack surface -- a mis-issued cert from
  any CA is irrelevant, only the key the zone owner signed is accepted;
* it directly ties "who Gate A said the server is" to "who TLS says we reached".

Flow:
  server: ssl_context_server(cert, key) -> wrap accepted TCP socket
  client: tcp connect -> wrap with ssl_context_client() (verification disabled
          in the library, because we do our own) -> handshake -> read peer cert
          -> require spki_sha256(peer_cert) == descriptor.spki_pin (constant
          time) -> only then send any SECDNS query.

Disabling the library's hostname/CA check and replacing it with an explicit pin
check is the correct, intended pattern here; the pin is a *stronger* check than
CA validation for this use case, not a weaker one.
"""
from __future__ import annotations

import socket
import ssl

from .crypto import ct_eq, spki_sha256


def ssl_context_server(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return ctx


def ssl_context_client() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    # We authenticate the server by SPKI pin from the signed descriptor, not by
    # CA chain or hostname, so we turn those off and do the pin check ourselves.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class PinMismatch(Exception):
    """Raised when the TLS peer's SPKI does not match the signed descriptor."""


def connect_pinned(host: str, port: int, spki_pin: bytes,
                   timeout: float = 5.0) -> ssl.SSLSocket:
    """Open TLS 1.3 to host:port and enforce the descriptor's SPKI pin."""
    raw = socket.create_connection((host, port), timeout=timeout)
    ctx = ssl_context_client()
    tls = ctx.wrap_socket(raw, server_hostname=None)
    peer_der = tls.getpeercert(binary_form=True)
    if peer_der is None:
        tls.close()
        raise PinMismatch("server presented no certificate")
    if not ct_eq(spki_sha256(peer_der), spki_pin):
        tls.close()
        raise PinMismatch("server SPKI does not match signed descriptor")
    return tls

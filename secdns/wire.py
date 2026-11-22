"""
secdns.wire -- SECDNS message framing.

Two transports, two jobs:

* Bootstrap (Gate A discovery) runs over the *untrusted* plain channel. The
  resolver asks the server for a zone's DescriptorBundle. We do not trust this
  channel at all; the bundle is self-authenticating via signatures, so a
  man-in-the-middle can only cause a verification failure, never a false
  accept. Bootstrap frames are JSON for readability (they are rare, one per
  zone per cache lifetime).

* Secure data (Gate B/C) runs *inside* TLS 1.3. Here we frame the actual DNS
  query and answer. The frame is binary and fixed:

      offset  size  field          meaning
      ------  ----  -------------  --------------------------------------------
      0       4     magic          ASCII "SDNS" (0x53 0x44 0x4E 0x53)
      4       1     version        SECDNS protocol version (currently 1)
      5       1     msg_type       1 = QUERY, 2 = ANSWER, 3 = ERROR
      6       8     nonce          per-query random, echoed in the answer; binds
                                   an answer to the exact outstanding query
                                   (freshness, G3) *inside* the TLS session
      14      2     dns_len        big-endian length of the DNS payload
      16      N     dns_payload    a standard RFC 1035 wire-format DNS message

  Because this frame only ever travels inside an authenticated, encrypted TLS
  1.3 record stream, it needs no signature of its own: TLS gives us secrecy,
  integrity and ordering on the channel. The nonce defends against an answer
  from an *earlier* query on the same connection being replayed for a later
  one (in-session binding); cross-connection replay is already impossible
  because TLS keys are per-connection.

The length prefix also gives us the Gate C size budget cheaply: we refuse to
read a dns_payload larger than MAX_DNS_BYTES before allocating for it.
"""
from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass

MAGIC = b"SDNS"
WIRE_VERSION = 1

MSG_QUERY = 1
MSG_ANSWER = 2
MSG_ERROR = 3

HEADER_LEN = 16
MAX_DNS_BYTES = 8192          # Gate C hard cap on a single DNS payload
NONCE_LEN = 8


def new_nonce() -> bytes:
    return os.urandom(NONCE_LEN)


@dataclass(frozen=True)
class Frame:
    msg_type: int
    nonce: bytes
    dns_payload: bytes

    def encode(self) -> bytes:
        if len(self.nonce) != NONCE_LEN:
            raise ValueError("nonce must be 8 bytes")
        if len(self.dns_payload) > MAX_DNS_BYTES:
            raise ValueError("dns payload exceeds MAX_DNS_BYTES")
        return (
            MAGIC
            + struct.pack(">B", WIRE_VERSION)
            + struct.pack(">B", self.msg_type)
            + self.nonce
            + struct.pack(">H", len(self.dns_payload))
            + self.dns_payload
        )

    @classmethod
    def decode(cls, buf: bytes) -> "Frame":
        if len(buf) < HEADER_LEN:
            raise ValueError("short frame header")
        if buf[:4] != MAGIC:
            raise ValueError("bad magic")
        version = buf[4]
        if version != WIRE_VERSION:
            raise ValueError(f"unsupported wire version {version}")
        msg_type = buf[5]
        nonce = buf[6:14]
        (dns_len,) = struct.unpack(">H", buf[14:16])
        if dns_len > MAX_DNS_BYTES:
            raise ValueError("dns_len exceeds MAX_DNS_BYTES")
        payload = buf[HEADER_LEN:HEADER_LEN + dns_len]
        if len(payload) != dns_len:
            raise ValueError("truncated dns payload")
        return cls(msg_type, nonce, payload)


# ---- length-delimited stream helpers (one frame per 2-byte length prefix) ---


def send_frame(sock, frame: Frame) -> None:
    body = frame.encode()
    sock.sendall(struct.pack(">H", len(body)) + body)


def recv_exact(sock, n: int) -> bytes:
    chunks = []
    got = 0
    while got < n:
        chunk = sock.recv(n - got)
        if not chunk:
            raise ConnectionError("peer closed mid-frame")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def recv_frame(sock) -> Frame:
    (outer_len,) = struct.unpack(">H", recv_exact(sock, 2))
    if outer_len > HEADER_LEN + MAX_DNS_BYTES:
        raise ValueError("outer frame too large")
    return Frame.decode(recv_exact(sock, outer_len))


# ---- bootstrap (plain, untrusted) request/response --------------------------


def encode_bootstrap_request(zone: str) -> bytes:
    return json.dumps({"t": "descriptor_request", "zone": zone}).encode()


def decode_bootstrap_request(data: bytes) -> str:
    d = json.loads(data.decode())
    if d.get("t") != "descriptor_request":
        raise ValueError("not a descriptor request")
    return d["zone"]


def encode_bootstrap_response(bundle_dict: dict) -> bytes:
    return json.dumps({"t": "descriptor_response", "bundle": bundle_dict}).encode()


def decode_bootstrap_response(data: bytes) -> dict:
    d = json.loads(data.decode())
    if d.get("t") != "descriptor_response":
        raise ValueError("not a descriptor response")
    return d["bundle"]

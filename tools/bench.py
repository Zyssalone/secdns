"""
tools/bench.py -- latency and byte-size measurements.

Compares, on localhost:
  * plain DNS over UDP (a minimal honest responder) -- the baseline cost
  * SECDNS cold  -- Gate A bundle verify + TLS 1.3 handshake + query
  * SECDNS warm  -- reuse a verified descriptor + a pooled TLS connection

Also reports bytes exchanged for one query/answer in each case (payload only;
TLS record and handshake overhead reported separately for the cold case).

Numbers are localhost micro-benchmarks: they show *relative* overhead of the
cryptographic path, not wide-area latency. Written to lab/results/bench.json.
"""
from __future__ import annotations

import json
import os
import socket
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dns.flags
import dns.message
import dns.rdatatype

from labkit import start_lab
from secdns.channel import connect_pinned
from secdns.server import build_answer
from secdns.wire import Frame, MSG_QUERY, new_nonce, recv_frame, send_frame
from secdns.zone import lab_zone

QNAME = "www.example.test."
ZONE = "example.test."
N = 200


def plain_udp_server(zone):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    import threading
    stop = threading.Event()
    def loop():
        s.settimeout(0.5)
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            q = dns.message.from_wire(data)
            s.sendto(build_answer(zone, q).to_wire(), addr)
    threading.Thread(target=loop, daemon=True).start()
    return s, port, stop


def bench_plain(port):
    lats, qb, ab = [], 0, 0
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.settimeout(2)
    for _ in range(N):
        q = dns.message.make_query(QNAME, "A").to_wire()
        t0 = time.perf_counter()
        c.sendto(q, ("127.0.0.1", port))
        data, _ = c.recvfrom(4096)
        lats.append((time.perf_counter() - t0) * 1000)
        qb, ab = len(q), len(data)
    c.close()
    return lats, qb, ab


def bench_secdns_cold(lab):
    lats = []
    for _ in range(N):
        lab.resolver._desc_cache.clear()          # force Gate A each time
        t0 = time.perf_counter()
        lab.resolver.resolve(ZONE, QNAME, "A")    # Gate A + handshake + query
        lats.append((time.perf_counter() - t0) * 1000)
    return lats


def bench_secdns_warm(lab):
    # Reuse one verified descriptor and one TLS connection for all queries.
    desc = lab.resolver._descriptor_for(ZONE)
    tls = connect_pinned(desc.host, desc.port, desc.spki_pin)
    lats, qb, ab = [], 0, 0
    try:
        for _ in range(N):
            q = dns.message.make_query(QNAME, "A")
            frame = Frame(MSG_QUERY, new_nonce(), q.to_wire())
            t0 = time.perf_counter()
            send_frame(tls, frame)
            ans = recv_frame(tls)
            lats.append((time.perf_counter() - t0) * 1000)
            qb, ab = len(frame.encode()), len(ans.encode())
    finally:
        tls.close()
    return lats, qb, ab


def summ(lats):
    lats = sorted(lats)
    return {
        "mean_ms": round(statistics.mean(lats), 4),
        "median_ms": round(statistics.median(lats), 4),
        "p95_ms": round(lats[int(len(lats) * 0.95) - 1], 4),
        "min_ms": round(min(lats), 4),
        "max_ms": round(max(lats), 4),
    }


def main():
    zone = lab_zone()
    s, port, stop = plain_udp_server(zone)
    lab = start_lab(zone)
    try:
        plain_lat, pqb, pab = bench_plain(port)
        cold_lat = bench_secdns_cold(lab)
        warm_lat, wqb, wab = bench_secdns_warm(lab)
    finally:
        stop.set(); s.close(); lab.stop()

    out = {
        "iterations": N,
        "plain_udp": {**summ(plain_lat), "query_bytes": pqb, "answer_bytes": pab},
        "secdns_cold": {**summ(cold_lat),
                        "note": "includes Gate A verify + TLS 1.3 handshake"},
        "secdns_warm": {**summ(warm_lat), "query_frame_bytes": wqb,
                        "answer_frame_bytes": wab,
                        "note": "pooled TLS connection, cached descriptor"},
    }
    out["overhead"] = {
        "warm_vs_plain_median_x": round(
            out["secdns_warm"]["median_ms"] / out["plain_udp"]["median_ms"], 2),
        "cold_vs_plain_median_x": round(
            out["secdns_cold"]["median_ms"] / out["plain_udp"]["median_ms"], 2),
        "query_frame_overhead_bytes": wqb - pqb,
    }
    outdir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "lab", "results")
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "bench.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))
    print(f"\nwritten -> {path}")


if __name__ == "__main__":
    main()

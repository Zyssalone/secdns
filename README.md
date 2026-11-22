# SECDNS — cryptographic hardening of the recursive→authoritative DNS hop

A proof-of-concept for **Challenge 2 (CSC 4308)**. SECDNS ("TriGate") secures the
recursive-resolver ↔ authoritative-server hop with three sequential gates:

- **Gate A — Authority.** Fetch a DNSSEC-style *signed service descriptor* and
  verify the chain `anchor → zone key → descriptor` before connecting.
- **Gate B — Channel.** TLS 1.3 to the descriptor's endpoint, authenticated by a
  **DANE-style SPKI pin** carried inside the signed descriptor (no public CA).
- **Gate C — Validation firewall.** Parse under a size/work budget; enforce
  question binding, bailiwick and cache provenance *before* cache insertion.

It uses only **vetted primitives**: Ed25519 (RFC 8032) and SHA-256 via
`cryptography`/OpenSSL, TLS 1.3 via the stdlib `ssl` module, RFC 1035 parsing via
`dnspython`. No cryptographic primitive is hand-rolled.

## Layout

```
secdns/        the library (crypto, descriptor, trustchain, channel, wire,
               validation, zone, server, resolver, legacy)
tools/         provision.py, labkit.py, demo.py, bench.py, make_figures.py
tests/         pytest suite (RFC 8032 + FIPS 180-4 vectors, chain, Gate C, e2e)
report/        build_report.py + figures/   ->  ../SECDNS_Report.docx
lab/           pki/ (generated keys & certs) and results/ (demo + bench JSON)
```

## Run it

```bash
python3 -m pip install dnspython cryptography

# everything runs on 127.0.0.1, no root, no external network
PYTHONPATH=.:tools python3 tools/provision.py --out lab/pki    # keys + certs
PYTHONPATH=.:tools python3 -m pytest tests/ -q                 # 36 tests
PYTHONPATH=.:tools python3 tools/demo.py                       # 7 attack/defence scenarios
PYTHONPATH=.:tools python3 tools/bench.py                      # latency + byte sizes
PYTHONPATH=.:tools python3 tools/make_figures.py               # regenerate figures
PYTHONPATH=.:tools python3 report/build_report.py              # rebuild the .docx
```

## What the demo shows

| # | Scenario | Gate that stops it |
|---|----------|--------------------|
| S1 | Off-path forged answer (Kaminsky / SAD DNS) | B (channel auth) |
| S2 | Rogue server, wrong TLS key (on-path MITM)  | B (SPKI pin) |
| S3 | Tampered service descriptor (bootstrap MITM)| A (signature chain) |
| S4 | Out-of-bailiwick injection (MaginotDNS)     | C (bailiwick) |
| S5 | High-cost answer (KeyTrap-style)            | C (work budget) |
| S6 | In-session answer replay                    | C (nonce) |
| S7 | Expired descriptor                          | A (validity window) |

The baseline **weak** resolver in `secdns/legacy.py` accepts S1/S4/S5; SECDNS
rejects all seven. No packets are spoofed on any network — the off-path
attacker's *success condition* (a reply matching the outstanding query) is fed
directly to each resolver's acceptance path, which keeps the comparison
deterministic and avoids building a network-poisoning tool.

## Safety / scope

Everything is an **isolated, in-process teaching lab**. The weak resolver is a
deliberately vulnerable teaching model, not a claim about how modern resolvers
are configured. SECDNS protects data *in transit on one hop*; it is not a
replacement for DNSSEC's offline verifiability, and key/authority compromise is
out of scope. See `../SECDNS_Report.docx` §9 for the full security analysis.

"""SECDNS -- a cryptographic resolver-to-authoritative DNS hardening PoC.

Package layout:
  crypto       Ed25519 + SPKI pin primitives (vetted library only)
  descriptor   Gate A signed objects (ZoneDelegation, ServiceDescriptor)
  trustchain   Gate A verification with typed reasons
  channel      Gate B TLS 1.3 transport with DANE-style SPKI pinning
  wire         SECDNS frame format (documented byte-by-byte)
  validation   Gate C validation firewall (question binding, bailiwick, budget)
  zone         minimal authoritative zone store
  server       SECDNS authoritative server (bootstrap + TLS data path)
  resolver     SECDNS recursive resolver (all three gates)
  legacy       deliberately weak "before" resolver for the baseline comparison
"""
__version__ = "0.1.0"

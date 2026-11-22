"""
tools/provision.py -- one-time key and descriptor provisioning for the lab.

Creates, under an output directory:
  anchor.pem          trust-anchor Ed25519 private key (the root KSK analogue)
  anchor.pub          its raw public key (what the resolver pins)
  zone.pem            the zone's Ed25519 signing key
  server.crt/.key     the SECDNS server's TLS 1.3 certificate + key
  bundle.json         DescriptorBundle (delegation + descriptor), signed

The server's SPKI hash is pinned into the signed descriptor, so the resolver
only needs anchor.pub to verify the whole chain and the TLS identity.

Run:  python3 -I tools/provision.py --out lab/pki --host 127.0.0.1 --port 8853
"""
from __future__ import annotations

import argparse
import datetime
import os
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secdns.crypto import SigningKey, spki_sha256          # noqa: E402
from secdns.descriptor import (DescriptorBundle, ServiceDescriptor,          # noqa: E402
                               ZoneDelegation)


def make_server_cert(cn: str):
    """Self-signed P-256 TLS cert. Identity comes from the pinned SPKI, not the
    CA chain or CN, so a self-signed cert is exactly right here."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return cert_pem, key_pem, spki_sha256(cert_der)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="lab/pki")
    ap.add_argument("--zone", default="example.test.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8853)
    ap.add_argument("--ttl-days", type=int, default=30)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    now = int(time.time())
    not_after = now + args.ttl_days * 86400

    anchor = SigningKey.generate()
    zone_key = SigningKey.generate()

    cert_pem, key_pem, pin = make_server_cert(args.host)

    dele = ZoneDelegation(args.zone, zone_key.public, now - 300,
                          not_after).signed_by(anchor)
    desc = ServiceDescriptor(args.zone, args.host, args.port, pin,
                             proto_version=1, not_before=now - 300,
                             not_after=not_after).signed_by(zone_key)
    bundle = DescriptorBundle(dele, desc)

    def w(name, data, mode="wb"):
        p = os.path.join(args.out, name)
        with open(p, mode) as f:
            f.write(data)
        return p

    w("anchor.pem", anchor.to_pem())
    w("anchor.pub", anchor.public.raw())
    w("zone.pem", zone_key.to_pem())
    w("server.crt", cert_pem)
    w("server.key", key_pem)
    import json
    w("bundle.json", json.dumps(bundle.to_dict(), indent=2).encode())

    print(f"provisioned zone {args.zone} -> {args.host}:{args.port}")
    print(f"  anchor key id : {anchor.public.key_id()}")
    print(f"  zone   key id : {zone_key.public.key_id()}")
    print(f"  SPKI pin      : {pin.hex()[:32]}...")
    print(f"  descriptor valid until : {not_after} "
          f"({args.ttl_days} days)")
    print(f"  files written to: {args.out}/")


if __name__ == "__main__":
    main()

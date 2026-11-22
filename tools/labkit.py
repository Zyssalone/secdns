"""
tools/labkit.py -- in-process lab harness.

Starts a bootstrap server + a TLS SECDNS server on ephemeral ports, builds a
signed DescriptorBundle whose endpoint matches the TLS server's real port, and
returns a ready SecureResolver plus the anchor. Everything runs on 127.0.0.1 in
one process, so the whole three-gate path can be exercised by the demo and by
pytest without external network or root.
"""
from __future__ import annotations

import os
import tempfile
import time
from dataclasses import dataclass

from secdns.crypto import SigningKey, spki_sha256
from secdns.descriptor import DescriptorBundle, ServiceDescriptor, ZoneDelegation
from secdns.resolver import SecureResolver
from secdns.server import SecureServer, start_bootstrap
from secdns.zone import Zone, lab_zone


def _server_cert(cn: str, tmp: str):
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    crt = os.path.join(tmp, "server.crt")
    k = os.path.join(tmp, "server.key")
    with open(crt, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(k, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pin = spki_sha256(cert.public_bytes(serialization.Encoding.DER))
    return crt, k, pin


@dataclass
class Lab:
    resolver: SecureResolver
    anchor: SigningKey
    zone_key: SigningKey
    secure_server: SecureServer
    bootstrap: object
    server_pin: bytes
    zone: Zone
    tmpdir: str

    def stop(self):
        self.secure_server.stop()
        self.bootstrap.shutdown()


def start_lab(zone: Zone | None = None, host: str = "127.0.0.1",
              desc_ttl: int = 3600) -> Lab:
    zone = zone or lab_zone()
    tmp = tempfile.mkdtemp(prefix="secdns-lab-")
    crt, key, pin = _server_cert(host, tmp)

    # Start the TLS data-path server first so we learn its real port.
    srv = SecureServer(host, 0, crt, key, zone)
    data_port = srv.start()

    now = int(time.time())
    anchor = SigningKey.generate()
    zone_key = SigningKey.generate()
    dele = ZoneDelegation(zone.origin, zone_key.public, now - 300,
                          now + desc_ttl).signed_by(anchor)
    desc = ServiceDescriptor(zone.origin, host, data_port, pin, 1,
                             now - 300, now + desc_ttl).signed_by(zone_key)
    bundle = DescriptorBundle(dele, desc)

    boot = start_bootstrap(host, 0, {zone.origin: bundle})
    boot_port = boot.server_address[1]

    resolver = SecureResolver(anchor.public, host, boot_port, strict=True)
    return Lab(resolver, anchor, zone_key, srv, boot, pin, zone, tmp)

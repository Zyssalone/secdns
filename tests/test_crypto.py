"""Crypto primitives, checked against official RFC 8032 / FIPS 180-4 vectors."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secdns.crypto import SigningKey, VerifyKey, sha256, spki_sha256, ct_eq


# -- RFC 8032 Section 7.1 Ed25519 test vectors ------------------------------
# TEST 1: empty message
V1_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
V1_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
V1_MSG = b""
V1_SIG = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
# TEST 2: one-byte message 0x72
V2_SEED = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
V2_PUB = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
V2_MSG = bytes.fromhex("72")
V2_SIG = bytes.fromhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")


def test_rfc8032_public_keys():
    assert SigningKey.from_seed(V1_SEED).public.raw() == V1_PUB
    assert SigningKey.from_seed(V2_SEED).public.raw() == V2_PUB


def test_rfc8032_signatures():
    assert SigningKey.from_seed(V1_SEED).sign(V1_MSG) == V1_SIG
    assert SigningKey.from_seed(V2_SEED).sign(V2_MSG) == V2_SIG


def test_rfc8032_verify():
    assert VerifyKey.from_raw(V1_PUB).verify(V1_SIG, V1_MSG)
    assert VerifyKey.from_raw(V2_PUB).verify(V2_SIG, V2_MSG)
    # wrong message must not verify
    assert not VerifyKey.from_raw(V1_PUB).verify(V1_SIG, b"x")
    # vector 1 signature under vector 2 key must not verify
    assert not VerifyKey.from_raw(V2_PUB).verify(V1_SIG, V1_MSG)


def test_fips180_sha256():
    # FIPS 180-4 / NIST known answer
    assert sha256(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


def test_pem_roundtrip():
    sk = SigningKey.generate()
    sk2 = SigningKey.from_pem(sk.to_pem())
    assert sk.public == sk2.public
    msg = b"roundtrip"
    assert sk2.public.verify(sk.sign(msg), msg)


def test_raw_roundtrip_and_equality():
    sk = SigningKey.generate()
    vk2 = VerifyKey.from_raw(sk.public.raw())
    assert vk2 == sk.public
    assert hash(vk2) == hash(sk.public)
    assert sk.public != SigningKey.generate().public


def test_tamper_detected():
    sk = SigningKey.generate()
    sig = bytearray(sk.sign(b"hello"))
    sig[0] ^= 0x01
    assert not sk.public.verify(bytes(sig), b"hello")


def test_ct_eq():
    assert ct_eq(b"abc", b"abc")
    assert not ct_eq(b"abc", b"abd")
    assert not ct_eq(b"abc", b"ab")


def test_spki_sha256_matches_self_signed():
    # a cert's SPKI pin is stable and 32 bytes
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    pin = spki_sha256(der)
    assert len(pin) == 32
    assert spki_sha256(der) == pin  # deterministic

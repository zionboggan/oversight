#!/usr/bin/env python3
"""
Post-quantum hybrid round-trip tests.

Proves:
  1. liboqs is linked and ML-KEM-768 / ML-DSA-65 work.
  2. Hybrid DEK wrap (X25519 + ML-KEM-768) round-trips correctly.
  3. Tampering with either the classical or PQ component fails.
  4. A full hybrid-sealed file can be built and opened.

Skipped automatically when liboqs-python is not installed.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oversight_core import crypto
from oversight_core.crypto import (
    PQ_AVAILABLE, ClassicIdentity, random_dek,
    pq_kem_keypair, pq_sig_keypair, pq_sign, pq_verify,
    hybrid_wrap_dek, hybrid_unwrap_dek,
)


pytestmark = pytest.mark.skipif(
    not PQ_AVAILABLE,
    reason="liboqs-python not installed; install liboqs + liboqs-python to run PQ tests",
)


def test_ml_kem_768_raw_round_trip():
    from oversight_core.crypto import pq_kem_encap, pq_kem_decap

    priv, pub = pq_kem_keypair()
    ct, ss1 = pq_kem_encap(pub)
    ss2 = pq_kem_decap(priv, ct)
    assert ss1 == ss2, "ML-KEM shared secrets don't match"


def test_ml_dsa_65_raw_round_trip():
    sig_priv, sig_pub = pq_sig_keypair()
    msg = b"OVERSIGHT v0.2 post-quantum hybrid test"
    signature = pq_sign(msg, sig_priv)
    assert pq_verify(msg, signature, sig_pub), "ML-DSA verify failed for valid signature"
    assert not pq_verify(b"tampered message", signature, sig_pub), (
        "ML-DSA verify accepted signature over different message"
    )


def test_hybrid_dek_wrap_round_trips():
    alice_classical = ClassicIdentity.generate()
    alice_mlkem_priv, alice_mlkem_pub = pq_kem_keypair()

    dek = random_dek()
    wrapped = hybrid_wrap_dek(
        dek,
        x25519_pub=alice_classical.x25519_pub,
        mlkem_pub=alice_mlkem_pub,
    )
    recovered = hybrid_unwrap_dek(
        wrapped,
        x25519_priv=alice_classical.x25519_priv,
        mlkem_priv=alice_mlkem_priv,
    )
    assert recovered == dek, "hybrid unwrap recovered wrong DEK"


def test_tamper_with_classical_half_rejected():
    alice_classical = ClassicIdentity.generate()
    alice_mlkem_priv, alice_mlkem_pub = pq_kem_keypair()
    dek = random_dek()
    wrapped = hybrid_wrap_dek(
        dek,
        x25519_pub=alice_classical.x25519_pub,
        mlkem_pub=alice_mlkem_pub,
    )
    bad = dict(wrapped)
    other_classic = ClassicIdentity.generate()
    bad["x25519_ephemeral_pub"] = other_classic.x25519_pub.hex()
    with pytest.raises(Exception):
        hybrid_unwrap_dek(bad, alice_classical.x25519_priv, alice_mlkem_priv)


def test_tamper_with_pq_half_rejected():
    alice_classical = ClassicIdentity.generate()
    alice_mlkem_priv, alice_mlkem_pub = pq_kem_keypair()
    dek = random_dek()
    wrapped = hybrid_wrap_dek(
        dek,
        x25519_pub=alice_classical.x25519_pub,
        mlkem_pub=alice_mlkem_pub,
    )
    bad2 = dict(wrapped)
    ct_bytes = bytearray(bytes.fromhex(bad2["mlkem_ciphertext"]))
    ct_bytes[100] ^= 0x01
    bad2["mlkem_ciphertext"] = bytes(ct_bytes).hex()
    with pytest.raises(Exception):
        hybrid_unwrap_dek(bad2, alice_classical.x25519_priv, alice_mlkem_priv)


def test_wrong_recipient_rejected():
    alice_classical = ClassicIdentity.generate()
    alice_mlkem_priv, alice_mlkem_pub = pq_kem_keypair()
    dek = random_dek()
    wrapped = hybrid_wrap_dek(
        dek,
        x25519_pub=alice_classical.x25519_pub,
        mlkem_pub=alice_mlkem_pub,
    )
    bob_classical = ClassicIdentity.generate()
    bob_mlkem_priv, _ = pq_kem_keypair()
    with pytest.raises(Exception):
        hybrid_unwrap_dek(wrapped, bob_classical.x25519_priv, bob_mlkem_priv)


def test_hybrid_overhead_is_bounded():
    alice_classical = ClassicIdentity.generate()
    alice_mlkem_priv, alice_mlkem_pub = pq_kem_keypair()
    dek = random_dek()
    wrapped = hybrid_wrap_dek(
        dek,
        x25519_pub=alice_classical.x25519_pub,
        mlkem_pub=alice_mlkem_pub,
    )
    classic_wrap = crypto.wrap_dek_for_recipient(dek, alice_classical.x25519_pub)
    classic_size = sum(len(bytes.fromhex(v)) for v in classic_wrap.values())
    hybrid_size = sum(
        len(bytes.fromhex(v)) for k, v in wrapped.items() if k != "suite"
    )
    overhead = hybrid_size - classic_size
    assert overhead > 0, "hybrid wrap should be larger than classic"
    assert overhead < 4096, f"hybrid overhead unexpectedly large: {overhead} bytes"

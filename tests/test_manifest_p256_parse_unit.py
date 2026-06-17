"""
test_manifest_p256_parse_unit
=============================
Regression test for the cross-language HW-P256 manifest parse bug.

Previously the Python manifest parser hard-rejected `p256_pub` as an unknown
recipient field, which made every Rust-sealed OSGT-HW-P256-v1 container
unopenable and uninspectable by Python. Rust is the forward canonical
implementation; Python keeps parse and inspect parity during the transition
but does not implement the HW-P256 seal/open crypto path. Canonicalization
of the field set is covered separately by the JCS-unification work.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oversight_core.manifest import Manifest, Recipient


def test_recipient_has_p256_pub_field():
    r = Recipient(recipient_id="alice", x25519_pub="00" * 32, p256_pub="ab" * 32)
    assert r.p256_pub == "ab" * 32


def test_p256_pub_defaults_none_so_classic_manifests_unchanged():
    r = Recipient(recipient_id="alice", x25519_pub="00" * 32)
    assert r.p256_pub is None


def test_manifest_from_json_accepts_p256_pub_recipient():
    payload = {
        "file_id": "00000000-0000-4000-8000-000000000000",
        "issued_at": 1700000000,
        "suite": "OSGT-HW-P256-v1",
        "recipient": {
            "recipient_id": "alice",
            "x25519_pub": "00" * 32,
            "p256_pub": "cd" * 32,
        },
    }
    m = Manifest.from_json(json.dumps(payload, sort_keys=True).encode("utf-8"))
    assert m.suite == "OSGT-HW-P256-v1"
    assert m.recipient is not None
    assert m.recipient.p256_pub == "cd" * 32


def test_classic_manifest_canonical_bytes_unchanged_by_new_field():
    # p256_pub defaults to None and must be stripped, so a classic manifest's
    # canonical bytes are byte-identical to before the field was added.
    r = Recipient(recipient_id="alice", x25519_pub="00" * 32)
    m = Manifest(
        file_id="00000000-0000-4000-8000-000000000000",
        issued_at=1700000000,
        recipient=r,
    )
    canon = m.canonical_bytes().decode("utf-8")
    assert "p256_pub" not in canon

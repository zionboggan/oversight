"""
test_policy_unit
================

Focused policy/container checks around successful-open counting.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oversight_core import (
    ClassicIdentity,
    Manifest,
    Recipient,
    content_hash,
    open_sealed,
    seal,
)
from oversight_core.policy import PolicyContext, PolicyViolation, record_open


def test_wrong_recipient_does_not_consume_open_count(tmp_path):
    issuer = ClassicIdentity.generate()
    alice = ClassicIdentity.generate()
    bob = ClassicIdentity.generate()
    plaintext = b"hello policy"
    recipient = Recipient(
        recipient_id="alice",
        x25519_pub=alice.x25519_pub.hex(),
        ed25519_pub=alice.ed25519_pub.hex(),
    )
    manifest = Manifest.new(
        "test.txt",
        content_hash(plaintext),
        len(plaintext),
        "issuer",
        issuer.ed25519_pub.hex(),
        recipient,
        "http://localhost:8765",
        "text/plain",
    )
    manifest.policy["max_opens"] = 1
    blob = seal(plaintext, manifest, issuer.ed25519_priv, alice.x25519_pub)

    ctx = PolicyContext(state_dir=tmp_path, mode="LOCAL_ONLY")
    try:
        open_sealed(blob, bob.x25519_priv, policy_ctx=ctx)
    except Exception:
        pass
    else:
        raise AssertionError("wrong recipient unexpectedly decrypted file")

    recovered, _ = open_sealed(blob, alice.x25519_priv, policy_ctx=ctx)
    assert recovered == plaintext


def test_registry_modes_fail_closed():
    issuer = ClassicIdentity.generate()
    alice = ClassicIdentity.generate()
    plaintext = b"hello policy"
    recipient = Recipient(
        recipient_id="alice",
        x25519_pub=alice.x25519_pub.hex(),
        ed25519_pub=alice.ed25519_pub.hex(),
    )
    manifest = Manifest.new(
        "test.txt",
        content_hash(plaintext),
        len(plaintext),
        "issuer",
        issuer.ed25519_pub.hex(),
        recipient,
        "http://localhost:8765",
        "text/plain",
    )
    manifest.policy["max_opens"] = 1
    for mode in ("REGISTRY", "HYBRID"):
        try:
            record_open(manifest, PolicyContext(mode=mode, registry_url="https://registry.test"))
        except PolicyViolation as exc:
            assert "refusing to fall back" in str(exc)
        else:
            raise AssertionError(f"{mode} should fail closed until implemented")

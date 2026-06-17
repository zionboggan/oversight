#!/usr/bin/env python3
"""Cross-language ML-KEM-768 hybrid KEM conformance: Python <-> Rust.

Proves the OSGT-HYBRID-v1 DEK-wrap construction is byte-identical across the
Python reference (`oversight_core.crypto.hybrid_wrap_dek`/`hybrid_unwrap_dek`)
and the Rust port (`oversight_crypto::hybrid_wrap_dek`/`hybrid_unwrap_dek`) in
both directions:

  [1] Rust recipient -> Python wraps -> Rust unwraps
  [2] Python recipient -> Rust wraps -> Python unwraps

Only ML-KEM *public* keys (1184 bytes) and the X25519 public key cross the
language boundary; each recipient holds its own private key in its native
form (Rust seed / Python liboqs expanded). Requires liboqs + liboqs-python;
SKIPS with a clear message otherwise (CI-safe).
"""

import json
import os
import subprocess
import sys

REPO = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, REPO)

from oversight_core.crypto import PQ_AVAILABLE, hybrid_unwrap_dek, hybrid_wrap_dek  # noqa: E402

CARGO = os.path.join(REPO, "oversight-rust", "Cargo.toml")
TARGET = os.environ.get("CARGO_TARGET_DIR", "/root/.cache/oversight-rust-target")


def rust(args):
    cmd = [
        "cargo", "run", "--manifest-path", CARGO, "--release", "-q",
        "-p", "oversight-crypto", "--example", "hybrid_kem_cli", "--",
    ] + args
    env = dict(os.environ, CARGO_TARGET_DIR=TARGET)
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        raise RuntimeError(f"rust helper failed: {proc.stderr}")
    return proc.stdout.strip()


def x25519_keypair():
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    sk = X25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return pub, priv


def mlkem_keypair():
    import oqs

    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pub = kem.generate_keypair()
    priv = kem.export_secret_key()
    return pub, priv


def main():
    if not PQ_AVAILABLE:
        print("SKIP cross-language hybrid KEM: liboqs-python not available")
        return 0

    dek = os.urandom(32)
    results = []

    # [1] Rust recipient -> Python wraps -> Rust unwraps.
    recv = json.loads(rust(["keygen"]))
    env = hybrid_wrap_dek(
        dek, bytes.fromhex(recv["x_pub"]), bytes.fromhex(recv["mlkem_pub"])
    )
    env_path = "/tmp/_oversight_hybrid_env1.json"
    with open(env_path, "w") as f:
        json.dump(env, f)
    dek_rs = bytes.fromhex(rust(["unwrap", env_path, recv["x_priv"], recv["mlkem_seed"]]))
    ok1 = dek_rs == dek
    results.append(ok1)
    print(f"[1] PY wrap -> RS unwrap: {'PASS' if ok1 else 'FAIL'}")

    # [2] Python recipient -> Rust wraps -> Python unwraps.
    x_pub, x_priv = x25519_keypair()
    mlkem_pub, mlkem_priv = mlkem_keypair()
    env2 = json.loads(rust(["wrap", x_pub.hex(), mlkem_pub.hex(), dek.hex()]))
    dek_py = hybrid_unwrap_dek(env2, x_priv, mlkem_priv)
    ok2 = dek_py == dek
    results.append(ok2)
    print(f"[2] RS wrap -> PY unwrap: {'PASS' if ok2 else 'FAIL'}")

    if all(results):
        print("CROSS-LANGUAGE HYBRID KEM: ALL PASS")
        return 0
    print("CROSS-LANGUAGE HYBRID KEM: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())

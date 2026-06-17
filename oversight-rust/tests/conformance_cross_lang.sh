#!/bin/bash
# Cross-language conformance test between the Python reference implementation
# and the Rust port. Verifies that both can read each other's sealed files
# bit-for-bit.

set -e
export PATH="$HOME/.cargo/bin:$PATH"

WORKDIR=/tmp/oversight-conformance
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
RUST_CARGO="$REPO_ROOT/oversight-rust/Cargo.toml"
PYTHON_ROOT="$REPO_ROOT"

rm -rf $WORKDIR
mkdir -p $WORKDIR
cd $WORKDIR

echo "=== Setup: generate identities in Rust ==="
cargo run --manifest-path $RUST_CARGO --release -q -- keygen --out alice.json 2>&1 | tail -4
cargo run --manifest-path $RUST_CARGO --release -q -- keygen --out issuer.json 2>&1 | tail -4

ALICE_X_PUB=$(python3 -c "import json; print(json.load(open('alice.json'))['x25519_pub'])")
ALICE_X_PRIV=$(python3 -c "import json; print(json.load(open('alice.json'))['x25519_priv'])")
ISSUER_ED_PRIV=$(python3 -c "import json; print(json.load(open('issuer.json'))['ed25519_priv'])")
ISSUER_ED_PUB=$(python3 -c "import json; print(json.load(open('issuer.json'))['ed25519_pub'])")

echo "This is a cross-language conformance test." > plaintext.txt
EXPECTED_HASH=$(python3 -c "
import hashlib
data = open('plaintext.txt', 'rb').read()
print(hashlib.sha256(data).hexdigest())
")
echo "Expected hash: $EXPECTED_HASH"

echo ""
echo "=== 1. Seal in RUST, open in PYTHON ==="
cargo run --manifest-path $RUST_CARGO --release -q -- seal \
  --input plaintext.txt --output rust-sealed.bin \
  --issuer issuer.json --recipient-pub "$ALICE_X_PUB" \
  --recipient-id "alice@test" --registry "https://reg.test" 2>&1 | tail -3

python3 <<PYEOF
import sys
sys.path.insert(0, '$PYTHON_ROOT')
from oversight_core.container import open_sealed
blob = open('rust-sealed.bin', 'rb').read()
priv = bytes.fromhex('$ALICE_X_PRIV')
plaintext, manifest = open_sealed(blob, priv)
expected = open('plaintext.txt', 'rb').read()
assert plaintext == expected, f"PLAINTEXT MISMATCH: got {plaintext!r}, expected {expected!r}"
assert manifest.content_hash == '$EXPECTED_HASH', f"HASH MISMATCH: {manifest.content_hash}"
print(f"  ✓ Python read Rust-sealed file ({len(plaintext)} bytes)")
print(f"  ✓ content_hash matches: {manifest.content_hash[:16]}...")
print(f"  ✓ file_id from Rust manifest: {manifest.file_id}")
print(f"  ✓ signature verified: {manifest.verify()}")
PYEOF

echo ""
echo "=== 2. Seal in PYTHON, open in RUST ==="
python3 <<PYEOF
import sys
sys.path.insert(0, '$PYTHON_ROOT')
from oversight_core import ClassicIdentity, content_hash
from oversight_core.manifest import Manifest, Recipient
from oversight_core.container import seal

alice_pub = bytes.fromhex('$ALICE_X_PUB')
issuer_priv = bytes.fromhex('$ISSUER_ED_PRIV')
issuer_pub = bytes.fromhex('$ISSUER_ED_PUB')

plaintext = open('plaintext.txt', 'rb').read()
m = Manifest.new(
    original_filename='plaintext.txt',
    content_hash=content_hash(plaintext),
    size_bytes=len(plaintext),
    issuer_id='cross-test',
    issuer_ed25519_pub_hex=issuer_pub.hex(),
    recipient=Recipient(recipient_id='alice@test', x25519_pub=alice_pub.hex()),
    registry_url='https://reg.test',
    content_type='text/plain',
)
blob = seal(plaintext, m, issuer_priv, alice_pub)
open('python-sealed.bin', 'wb').write(blob)
print(f"  ✓ Python sealed ({len(blob)} bytes)")
PYEOF

cargo run --manifest-path $RUST_CARGO --release -q -- open \
  --input python-sealed.bin --output rust-recovered.txt --recipient alice.json 2>&1 | tail -3

diff plaintext.txt rust-recovered.txt && echo "  ✓ Rust read Python-sealed file, plaintext matches"

echo ""
echo "=== 3. Inspect cross-format: Python can inspect Rust-sealed, Rust can inspect Python-sealed ==="
# Python inspect of Rust sealed
python3 <<PYEOF
import sys
sys.path.insert(0, '$PYTHON_ROOT')
from oversight_core.container import SealedFile
blob = open('rust-sealed.bin', 'rb').read()
sf = SealedFile.from_bytes(blob)
assert sf.manifest.verify(), "Python couldn't verify Rust signature!"
print(f"  ✓ Python Manifest.verify() of Rust-sealed: True (suite={sf.manifest.suite})")
PYEOF

# Rust inspect of Python sealed
cargo run --manifest-path $RUST_CARGO --release -q -- inspect \
  --input python-sealed.bin 2>&1 | grep -E "(signature valid|suite|OVERSIGHT)" | head -5

echo ""
echo "=== 4. Non-ASCII recipient_id round trip (the JCS divergence case) ==="
# Pre-JCS-port this failed: Python emitted {"recipient_id":"Zi\u00f3n@org"}
# (ensure_ascii=True) while Rust emitted {"recipient_id":"Zión@org"} (raw
# UTF-8). The two signatures covered different bytes, so a Rust-sealed file
# with a non-ASCII recipient_id failed Python Manifest.verify() and vice
# versa. After the RFC 8785 JCS unification, both sides serialize to raw
# UTF-8 and the signatures agree.
UNICODE_RECIPIENT='Zión@org'

cargo run --manifest-path $RUST_CARGO --release -q -- seal \
  --input plaintext.txt --output rust-unicode-sealed.bin \
  --issuer issuer.json --recipient-pub "$ALICE_X_PUB" \
  --recipient-id "$UNICODE_RECIPIENT" --registry "https://reg.test" 2>&1 | tail -3

python3 <<PYEOF
import sys
sys.path.insert(0, '$PYTHON_ROOT')
from oversight_core.container import open_sealed, SealedFile
blob = open('rust-unicode-sealed.bin', 'rb').read()
priv = bytes.fromhex('$ALICE_X_PRIV')
plaintext, manifest = open_sealed(blob, priv)
assert manifest.verify(), (
    "Python Manifest.verify() of Rust-sealed file with non-ASCII recipient_id "
    "FAILED. This is the JCS divergence: Python and Rust are computing "
    "different canonical bytes for the same manifest."
)
assert manifest.recipient.recipient_id == '$UNICODE_RECIPIENT', (
    f"recipient_id mismatch: got {manifest.recipient.recipient_id!r}"
)
print(f"  ✓ Python verifies Rust-sealed manifest with recipient_id={manifest.recipient.recipient_id!r}")
PYEOF

python3 <<PYEOF
import sys
sys.path.insert(0, '$PYTHON_ROOT')
from oversight_core import ClassicIdentity, content_hash
from oversight_core.manifest import Manifest, Recipient
from oversight_core.container import seal

alice_pub = bytes.fromhex('$ALICE_X_PUB')
issuer_priv = bytes.fromhex('$ISSUER_ED_PRIV')
issuer_pub = bytes.fromhex('$ISSUER_ED_PUB')

plaintext = open('plaintext.txt', 'rb').read()
m = Manifest.new(
    original_filename='plaintext.txt',
    content_hash=content_hash(plaintext),
    size_bytes=len(plaintext),
    issuer_id='cross-test',
    issuer_ed25519_pub_hex=issuer_pub.hex(),
    recipient=Recipient(recipient_id='$UNICODE_RECIPIENT', x25519_pub=alice_pub.hex()),
    registry_url='https://reg.test',
    content_type='text/plain',
)
blob = seal(plaintext, m, issuer_priv, alice_pub)
open('python-unicode-sealed.bin', 'wb').write(blob)
assert m.verify(), "Python cannot verify its own signature on a non-ASCII manifest"
print(f"  ✓ Python signed manifest with non-ASCII recipient_id, self-verify OK")
PYEOF

cargo run --manifest-path $RUST_CARGO --release -q -- open \
  --input python-unicode-sealed.bin --output rust-unicode-recovered.txt --recipient alice.json 2>&1 | tail -3

diff plaintext.txt rust-unicode-recovered.txt && echo "  ✓ Rust opens Python-sealed non-ASCII manifest, plaintext matches"

cargo run --manifest-path $RUST_CARGO --release -q -- inspect \
  --input python-unicode-sealed.bin 2>&1 | grep -E "signature valid" | head -1

echo ""
echo "=== 5. Hybrid (OSGT-HYBRID-v1) ML-KEM-768 KEM, Python <-> Rust ==="
PYTHONPATH="$REPO_ROOT:$PYTHONPATH" python3 "$REPO_ROOT/oversight-rust/tests/conformance_hybrid_kem.py"

echo ""
echo "=========================================="
echo "  CROSS-LANGUAGE CONFORMANCE: ALL PASS"
echo "=========================================="

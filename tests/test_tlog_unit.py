"""
test_tlog_unit
==============

Focused transparency-log checks around RFC 6962 behavior.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oversight_core.tlog import TransparencyLog


def ok(msg):
    print(f"  [PASS] {msg}")


def t1_empty_tree_root_matches_rfc6962():
    td = ROOT / ".tmp-tests" / f"tlog-{uuid.uuid4().hex}"
    td.mkdir(parents=True, exist_ok=False)
    try:
        tlog = TransparencyLog(td)
        assert tlog.size() == 0
        assert tlog.root() == hashlib.sha256(b"").digest()
    finally:
        shutil.rmtree(td, ignore_errors=True)
    ok("empty transparency log root matches RFC 6962")


def t2_reopen_rejects_corrupt_leaf_record():
    td = ROOT / ".tmp-tests" / f"tlog-{uuid.uuid4().hex}"
    td.mkdir(parents=True, exist_ok=False)
    try:
        (td / "leaves.jsonl").write_text("{not-json}\n", encoding="utf-8")
        try:
            TransparencyLog(td)
        except ValueError:
            pass
        else:
            raise AssertionError("corrupt tlog leaf should fail closed on load")
    finally:
        shutil.rmtree(td, ignore_errors=True)
    ok("corrupt transparency log leaf fails closed on load")


def t3_range_records_validate_disk_leaf_hashes():
    td = ROOT / ".tmp-tests" / f"tlog-{uuid.uuid4().hex}"
    td.mkdir(parents=True, exist_ok=False)
    try:
        tlog = TransparencyLog(td)
        tlog.append({"event": "register", "file_id": "f1"})
        records = tlog.range_records(0, 1)
        assert records[0]["index"] == 0
        assert "leaf_data_hex" in records[0]

        rec = json.loads((td / "leaves.jsonl").read_text(encoding="utf-8"))
        rec["leaf_data"] = "tampered"
        rec.pop("leaf_data_hex", None)
        (td / "leaves.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
        try:
            tlog.range_records(0, 1)
        except ValueError as exc:
            assert "leaf hash mismatch" in str(exc)
        else:
            raise AssertionError("tampered leaf should fail closed during range read")
    finally:
        shutil.rmtree(td, ignore_errors=True)
    ok("range_records validates leaf payload hashes")


def main():
    tmp_root = ROOT / ".tmp-tests"
    tmp_root.mkdir(exist_ok=True)
    print("=" * 60)
    print("  oversight_core.tlog - focused unit tests")
    print("=" * 60)
    t1_empty_tree_root_matches_rfc6962()
    t2_reopen_rejects_corrupt_leaf_record()
    t3_range_records_validate_disk_leaf_hashes()
    print()
    print("  ALL TESTS PASSED - 3/3")


if __name__ == "__main__":
    main()

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


def test_empty_tree_root_matches_rfc6962(tmp_path):
    tlog = TransparencyLog(tmp_path)
    assert tlog.size() == 0
    assert tlog.root() == hashlib.sha256(b"").digest()


def test_reopen_rejects_corrupt_leaf_record(tmp_path):
    (tmp_path / "leaves.jsonl").write_text("{not-json}\n", encoding="utf-8")
    try:
        TransparencyLog(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("corrupt tlog leaf should fail closed on load")


def test_range_records_validate_disk_leaf_hashes(tmp_path):
    tlog = TransparencyLog(tmp_path)
    tlog.append({"event": "register", "file_id": "f1"})
    records = tlog.range_records(0, 1)
    assert records[0]["index"] == 0
    assert "leaf_data_hex" in records[0]

    rec = json.loads((tmp_path / "leaves.jsonl").read_text(encoding="utf-8"))
    rec["leaf_data"] = "tampered"
    rec.pop("leaf_data_hex", None)
    (tmp_path / "leaves.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
    try:
        tlog.range_records(0, 1)
    except ValueError as exc:
        assert "leaf hash mismatch" in str(exc)
    else:
        raise AssertionError("tampered leaf should fail closed during range read")

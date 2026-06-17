"""
test_xff_spoof_unit
===================
Regression test for the X-Forwarded-For source-IP spoofing bug in the
registry rate limiter and beacon source_ip attribution.

Background: _xff_client must return the RIGHTMOST XFF entry (appended by
the directly-connected trusted proxy, e.g. Caddy), never the leftmost. The
leftmost is attacker-controlled because a client may send any XFF header
and the proxy appends rather than replaces. Trusting the leftmost let an
attacker pick their rate-limit bucket and forge the source_ip written into
beacon events and the transparency log.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from registry.server import _xff_client


def test_xff_ignores_spoofed_left_entries():
    assert _xff_client("1.2.3.4, 9.9.9.9") == "9.9.9.9"
    assert _xff_client("fake, fake2, 203.0.113.7") == "203.0.113.7"


def test_xff_single_entry_is_returned():
    assert _xff_client("9.9.9.9") == "9.9.9.9"


def test_xff_whitespace_only_entries_dropped():
    assert _xff_client(" , , 9.9.9.9") == "9.9.9.9"


def test_xff_empty_returns_none():
    assert _xff_client("") is None
    assert _xff_client("   ") is None
    assert _xff_client(" , ") is None

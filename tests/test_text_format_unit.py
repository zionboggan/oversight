"""
test_text_format_unit
=====================

Focused checks for the text format adapter's layer ordering.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from oversight_core import watermark
from oversight_core.formats import text as text_format


def test_text_adapter_matches_core_order():
    original = (
        "We begin to show how this is significant and we must help users find answers.\n"
        "A second paragraph helps the semantic watermark choose visible variants."
    )
    mark_id = watermark.new_mark_id()
    via_adapter = text_format.apply(original, mark_id, layers=("L1", "L2", "L3"))
    via_core = watermark.apply_all(original, mark_id, include_l3=True)
    assert via_adapter == via_core, "text adapter diverged from core watermark order"

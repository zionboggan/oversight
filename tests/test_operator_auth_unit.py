"""
test_operator_auth_unit
=======================
Regression test for the registry operator-auth fail-closed boot gate.

The registry must refuse to start when OVERSIGHT_OPERATOR_TOKEN is empty
unless OVERSIGHT_AUTH_DISABLED=1 is set explicitly. Without this gate, the
public write endpoints (/register, /attribute) let anyone self-sign manifests
into the append-only transparency log.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import registry.server as server


def _set(token: str, disabled: bool):
    server.OPERATOR_TOKEN = token
    server.AUTH_DISABLED = disabled


def test_no_token_not_disabled_refuses_to_boot():
    _set("", False)
    with pytest.raises(RuntimeError, match="OVERSIGHT_OPERATOR_TOKEN is required"):
        server._enforce_auth_config()


def test_no_token_but_disabled_boots_with_warning(recwarn):
    _set("", True)
    server._enforce_auth_config()
    assert any(
        "OVERSIGHT_AUTH_DISABLED" in str(w.message) for w in recwarn.list
    ), "expected a loud warning when auth is explicitly disabled"


def test_token_set_boots_cleanly():
    _set("a-real-operator-token-value", False)
    server._enforce_auth_config()


def test_token_set_boots_cleanly_even_if_disabled():
    _set("a-real-operator-token-value", True)
    server._enforce_auth_config()

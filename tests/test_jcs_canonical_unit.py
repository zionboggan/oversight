"""
test_jcs_canonical_unit
=======================

Byte-exact fixtures for the JSON Canonicalization Scheme (RFC 8785) port.

Background: the Rust reference uses ``serde_jcs::to_vec`` everywhere it
canonicalizes for signing or hashing. Python was historically on
``json.dumps(sort_keys=True, separators=(",",":")).encode("utf-8")``, which is
byte-identical to JCS for the ASCII-only subset but diverges for any non-ASCII
string value, because Python's default ``ensure_ascii=True`` escapes non-ASCII
as ``\\uXXXX`` while JCS emits raw UTF-8. That divergence was a latent threat
to the "bit-identical / conformance is ground truth" claim: any manifest,
tlog leaf, or evidence bundle containing a non-ASCII character would hash and
sign to different bytes across the two implementations.

These tests pin the JCS algorithm itself on known vectors (so a future
refactor cannot silently regress it), prove the non-ASCII divergence is
closed (the actual bug fix), and prove no regression for the existing
ASCII-only content (so committed fixtures and existing signatures stay valid).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oversight_core.jcs import jcs_dumps


def test_primitives():
    assert jcs_dumps(None) == b"null"
    assert jcs_dumps(True) == b"true"
    assert jcs_dumps(False) == b"false"
    assert jcs_dumps(0) == b"0"
    assert jcs_dumps(42) == b"42"
    assert jcs_dumps(-1) == b"-1"
    assert jcs_dumps(9223372036854775807) == b"9223372036854775807"
    assert jcs_dumps("hello") == b'"hello"'
    assert jcs_dumps("") == b'""'
    assert jcs_dumps([]) == b"[]"
    assert jcs_dumps({}) == b"{}"


def test_key_sorting_nested():
    assert jcs_dumps({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert jcs_dumps({"z": 1, "a": {"y": 2, "x": 3}}) == b'{"a":{"x":3,"y":2},"z":1}'
    assert jcs_dumps([3, 1, 2]) == b"[3,1,2]"


def test_string_escapes():
    assert jcs_dumps('a"b') == b'"a\\"b"'
    assert jcs_dumps("a\\b") == b'"a\\\\b"'
    assert jcs_dumps("a\nb") == b'"a\\nb"'
    assert jcs_dumps("a\tb") == b'"a\\tb"'
    assert jcs_dumps("a\rb") == b'"a\\rb"'
    assert jcs_dumps("a\bb") == b'"a\\bb"'
    assert jcs_dumps("a\fb") == b'"a\\fb"'
    assert jcs_dumps("a\x01b") == b'"a\\u0001b"'


def test_non_ascii_emits_raw_utf8_not_uXXXX_escape():
    # This is the central regression: pre-port Python emitted
    # b'{"name":"caf\\u00e9"}' here, which diverged from serde_jcs and broke
    # cross-language signature agreement. JCS emits raw UTF-8.
    assert jcs_dumps({"name": "café"}) == b'{"name":"caf\xc3\xa9"}'
    # CJK: 日 = U+65E5 -> E6 97 A5, 本 = U+672C -> E6 9C AC
    assert jcs_dumps({"k": "日本"}) == b'{"k":"\xe6\x97\xa5\xe6\x9c\xac"}'
    # Supplementary plane (surrogate pair in UTF-16): 𝄞 = U+1D11E -> F0 9D 84 9E
    assert jcs_dumps({"k": "𝄞"}) == b'{"k":"\xf0\x9d\x84\x9e"}'


def test_non_ascii_key_sort_order():
    # Keys: "abc" (00 61 00 62 00 63), "z" (00 7A), "ñ" (00 F1).
    # UTF-16-BE byte order: "abc" < "z" < "ñ". Python code-point sort agrees.
    out = jcs_dumps({"ñ": 3, "z": 2, "abc": 1})
    assert out == b'{"abc":1,"z":2,"\xc3\xb1":3}'


def test_floats_rejected():
    try:
        jcs_dumps(1.0)
        raise AssertionError("jcs_dumps accepted a float")
    except TypeError:
        pass
    try:
        jcs_dumps({"x": 1.5})
        raise AssertionError("jcs_dumps accepted a nested float")
    except TypeError:
        pass


def test_unsupported_types_rejected():
    for bad in (object(), b"bytes", set(), frozenset()):
        try:
            jcs_dumps(bad)
            raise AssertionError(f"jcs_dumps accepted {type(bad).__name__}")
        except TypeError:
            pass


def test_ascii_content_byte_identical_to_legacy_sort_keys():
    # For the ASCII-only, no-floats subset, JCS and the legacy sort_keys form
    # must produce identical bytes. This is what guarantees that every
    # existing ASCII manifest, tlog leaf, and evidence bundle continues to
    # verify after the port.
    samples = [
        {"event": "register", "file_id": "f0", "n": 3},
        {"a": ["x", "y"], "b": {"c": True, "d": None}},
        {"size": 7, "root": "00" * 32, "signature": "ab" * 64},
    ]
    for s in samples:
        legacy = json.dumps(s, sort_keys=True, separators=(",", ":")).encode("utf-8")
        assert jcs_dumps(s) == legacy, (
            f"ASCII divergence!\n  legacy: {legacy!r}\n  jcs:    {jcs_dumps(s)!r}"
        )


def test_tuple_serializes_like_list():
    assert jcs_dumps((1, 2, 3)) == b"[1,2,3]"


def test_round_trip_through_json_parser():
    # Canonical bytes must round-trip through a strict JSON parser.
    cases = [
        {"a": 1, "b": [True, None, "x"], "c": {"d": "café"}},
        {"issuer": "Zión@test", "hash": "ab" * 16},
    ]
    for c in cases:
        rt = json.loads(jcs_dumps(c).decode("utf-8"))
        assert rt == c

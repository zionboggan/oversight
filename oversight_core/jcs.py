"""
oversight_core.jcs
==================

JSON Canonicalization Scheme (RFC 8785) for Oversight.

Byte-exact match with the Rust reference's ``serde_jcs::to_vec``. Every
canonical-bytes computation that gets hashed or signed in Oversight flows
through ``jcs_dumps``: manifest signing, transparency-log leaf payloads,
DSSE statement payloads, evidence bundles, and registry sidecar comparison.

Vendored rather than pip-installed. Rationale: the canonicalization function
sits on the signing path of a cryptographic protocol, so every line must be
auditable in-tree, and the Oversight manifest schema carries no floats so we
implement only the RFC 8785 subset we need and reject floats explicitly rather
than silently producing a non-canonical float form.
"""

from __future__ import annotations

from typing import Any

_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
}


def jcs_dumps(obj: Any) -> bytes:
    """Canonicalize ``obj`` to RFC 8785 JSON bytes matching ``serde_jcs``.

    Accepts None, bool, int, str, list, tuple, dict. Floats and any other
    type raise TypeError; Oversight manifests use only int and str for
    numeric values, and silently emitting a non-canonical float form would
    break cross-language signature agreement.
    """
    parts: list[str] = []
    _serialize(obj, parts)
    return "".join(parts).encode("utf-8")


def _serialize(obj: Any, parts: list[str]) -> None:
    if obj is None:
        parts.append("null")
    elif obj is True:
        parts.append("true")
    elif obj is False:
        parts.append("false")
    elif isinstance(obj, int):
        parts.append(str(obj))
    elif isinstance(obj, float):
        raise TypeError(
            "JCS: floats are unsupported; Oversight manifests store every "
            "numeric value as int or string"
        )
    elif isinstance(obj, str):
        _serialize_str(obj, parts)
    elif isinstance(obj, (list, tuple)):
        parts.append("[")
        for i, item in enumerate(obj):
            if i:
                parts.append(",")
            _serialize(item, parts)
        parts.append("]")
    elif isinstance(obj, dict):
        parts.append("{")
        # RFC 8785 §3.2.3: keys sorted by UTF-16 code unit. For well-formed
        # Unicode this is equivalent to Python's default code-point sort
        # because BMP code units and supplementary-plane code points preserve
        # their relative order under both encodings. Encode as UTF-16-BE so
        # the sort key is explicit and matches serde_jcs byte ordering.
        items = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        for i, (k, v) in enumerate(items):
            if not isinstance(k, str):
                raise TypeError(
                    f"JCS: dict keys must be str, got {type(k).__name__}"
                )
            if i:
                parts.append(",")
            _serialize_str(k, parts)
            parts.append(":")
            _serialize(v, parts)
        parts.append("}")
    else:
        raise TypeError(f"JCS: unsupported type {type(obj).__name__}")


def _serialize_str(s: str, parts: list[str]) -> None:
    parts.append('"')
    for ch in s:
        cp = ord(ch)
        if cp == 0x22:
            parts.append('\\"')
        elif cp == 0x5C:
            parts.append("\\\\")
        elif cp < 0x20:
            parts.append(_SHORT_ESCAPES.get(cp, f"\\u{cp:04x}"))
        else:
            parts.append(ch)
    parts.append('"')

#!/usr/bin/env python3
"""Fail when strict source paths gain prose comments."""

from __future__ import annotations

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STRICT_COMMENT_FREE_DIRS = (
    ROOT / "oversight-rust" / "oversight-registry" / "src",
)
RUST_EXTENSIONS = {".rs"}
COMMENT_PREFIXES = ("//", "///", "//!")


def iter_source_files() -> list[Path]:
    files: list[Path] = []
    for directory in STRICT_COMMENT_FREE_DIRS:
        if directory.exists():
            files.extend(
                path
                for path in directory.rglob("*")
                if path.is_file() and path.suffix in RUST_EXTENSIONS
            )
    return sorted(files)


def comment_violations(path: Path) -> list[tuple[int, str]]:
    violations: list[tuple[int, str]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.lstrip()
        if stripped.startswith(COMMENT_PREFIXES):
            violations.append((lineno, line.rstrip()))
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--list-paths",
        action="store_true",
        help="Print strict paths before checking.",
    )
    args = parser.parse_args()

    if args.list_paths:
        for directory in STRICT_COMMENT_FREE_DIRS:
            print(directory.relative_to(ROOT))

    failures: list[str] = []
    for path in iter_source_files():
        for lineno, line in comment_violations(path):
            failures.append(f"{path.relative_to(ROOT)}:{lineno}: {line}")

    if failures:
        print("Comment-style violations:")
        print("\n".join(failures))
        return 1

    print("source comment style ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

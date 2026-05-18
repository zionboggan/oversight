# Contributing

## Code style

Oversight is security protocol code, so implementation files should read like
code first.

- Prefer clear names, small functions, and tests over explanatory inline
  comments.
- Do not add prose comments for ordinary control flow, configuration loading,
  route setup, or obvious validation.
- Keep comments only when they document a non-obvious protocol invariant,
  external wire-format requirement, compatibility constraint, or security
  boundary that code alone cannot make explicit.
- When a comment is necessary, keep it short and factual. Avoid conversational
  sentences and implementation diary notes.

Public documentation belongs in `docs/`, not in source-file commentary.

The strictest paths are enforced by `scripts/check_source_comments.py`; run it
before pushing changes in the Rust registry.

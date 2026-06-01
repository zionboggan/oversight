# Registry v1 Stability Note

Status: v1.0 candidate profile, dated 2026-05-31. The registry v1 surface is
still formally draft until the first v1.0 release tag, but the wire contract
described here is the compatibility target for operator burn-in.

This note exists so independent registry operators can tell which parts of the
current spec are expected to remain stable, which parts may still change before
v1.0, and what kind of change would require a new compatibility profile.

## Candidate-Frozen Surface

The following route shapes and response families are candidate-frozen for the
v1.0 line:

- `GET /health`
- `GET /.well-known/oversight-registry`
- `POST /register`
- `POST /attribute`
- `POST /dns_event`
- `GET /evidence/{file_id}`
- `GET /tlog/head`
- `GET /tlog/proof/{index}`
- `GET /tlog/range`
- `GET /p/{token_id}.png`
- `GET /r/{token_id}` and `GET /ocsp/r/{token_id}`
- `GET /v/{token_id}` and `GET /lic/v/{token_id}`
- `GET /candidates/semantic`

The canonical JSON manifest-signature rules, sidecar equality rule, identifier
length ceiling, DNS bridge authentication rule, operator-token header contract,
evidence-bundle core fields, local tlog leaf record fields, and standard error
envelope are also candidate-frozen.

## Compatibility Rules

A compatible implementation MAY add optional fields to JSON objects when older
clients can ignore them safely. A compatible implementation MUST NOT remove
fields, rename fields, change endpoint paths, change canonicalization, weaken
authentication requirements, or return framework-native error shapes instead of
the registry v1 error envelope.

The standard error envelope is:

```json
{"error":{"code":"not_found","message":"unknown file_id"}}
```

The current code vocabulary is `missing_field`, `signature_invalid`,
`sidecar_mismatch`, `issuer_mismatch`, `auth_required`, `rate_limited`,
`not_found`, and `server_error`.

## Conformance Gate

`tests/test_registry_conformance.py` is the executable compatibility gate. As
of this note it runs 38 checks against either the in-process Python reference
registry or a live operator URL:

```bash
OVERSIGHT_REGISTRY_URL=https://registry.example.org \
  python3 tests/test_registry_conformance.py
```

Passing the harness is required for an operator to claim registry v1 candidate
compatibility. The harness currently checks identity, liveness, registration,
manifest-signature rejection, sidecar rejection, attribution, evidence bundles,
tlog head/range shape, browser CORS, beacon routes, DNS-event fail-closed
behavior, and representative error-envelope codes.

## Changes That Require a New Profile

The following changes are breaking and require a new profile name or a v2 draft:

- Changing manifest canonicalization or signature-verification bytes.
- Accepting unsigned beacon or watermark sidecars as registry authority.
- Removing or renaming required evidence-bundle fields.
- Changing tlog leaf hashing or inclusion-proof shape.
- Allowing unauthenticated non-loopback DNS events.
- Changing route paths or making a required route optional.
- Returning non-envelope errors for registry failures.

## Remaining v1.0 Gates

Before the first v1.0 release tag, the project still needs:

1. Longer-running burn-in against a migrated operator database.
2. A final live conformance run against the public deployment target.
3. A release note naming the exact `tests/test_registry_conformance.py` count.
4. A v1.0 tag that freezes this profile for downstream implementers.

Until those gates close, this document is a candidate freeze, not a final
standards claim.

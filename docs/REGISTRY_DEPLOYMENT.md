# Registry Deployment

This is the public-safe live configuration for the reference Oversight
registry. It keeps secrets in `.env`, keeps the registry process off the public
host interface, and exposes TLS through Caddy. The Python FastAPI registry and
the Rust Axum registry both honor the write-side operator token described here.

## Layout

- `Dockerfile` builds the Python reference registry image.
- `docker-compose.yml` runs the registry on loopback and adds a `live` profile
  for Caddy.
- `Caddyfile` routes the registry, beacon, OCSP-style, and license-style
  hostnames to the registry container.
- `.env.example` lists every live setting without carrying secret values.

## First Run

```bash
cp .env.example .env
# Fill OVERSIGHT_DNS_EVENT_SECRET and OVERSIGHT_OPERATOR_TOKEN in .env.
# Use high-entropy random values; never commit .env.

docker compose up -d oversight-registry
curl http://127.0.0.1:8765/health
```

For public TLS, point DNS for the four configured hostnames at the host, then
start the live profile:

```bash
docker compose --profile live up -d
```

## Public Routes

`OVERSIGHT_REGISTRY_DOMAIN` serves the registry metadata, evidence, tlog, and
operator routes:

- `GET /health`
- `GET /.well-known/oversight-registry`
- `GET /evidence/{file_id}`
- `GET /tlog/head`
- `GET /tlog/proof/{index}`
- `GET /tlog/range`
- `GET /candidates/semantic`
- `POST /register`
- `POST /attribute`
- `POST /dns_event`

The beacon hostnames route only their beacon families:

- `OVERSIGHT_BEACON_DOMAIN`: `/p/{token}.png`
- `OVERSIGHT_OCSP_DOMAIN`: `/r/{token}` and `/ocsp/r/{token}`
- `OVERSIGHT_LICENSE_DOMAIN`: `/v/{token}` and `/lic/v/{token}`

Everything else returns `404`.

## Operator Authentication

If `OVERSIGHT_OPERATOR_TOKEN` is set, `POST /register` and `POST /attribute`
require either:

```http
Authorization: Bearer <token>
```

or:

```http
X-Oversight-Operator-Token: <token>
```

Leaving `OVERSIGHT_OPERATOR_TOKEN` empty keeps the v1 conformance harness and
local development behavior unchanged. Do not leave it empty on a public
operator deployment. Both reference registry implementations use the same
token contract, so live conformance commands work against either backend.

DNS bridge callbacks are separate. Set `OVERSIGHT_DNS_EVENT_SECRET`; the DNS
bridge must send either `Authorization: Bearer <secret>` or
`X-Oversight-DNS-Secret: <secret>` when posting `/dns_event`.

## Conformance

Local reference check:

```bash
python tests/test_registry_conformance.py
```

Live check against a token-protected registry:

```bash
OVERSIGHT_REGISTRY_URL=https://registry.example.org \
OVERSIGHT_OPERATOR_TOKEN=<token> \
python tests/test_registry_conformance.py
```

The token is read from the environment and sent as a bearer header. Do not put
real token values in shell history on shared machines.

## Migrating Python Registry Data To Rust

The Rust Axum registry can import the Python reference registry's SQLite rows
without mutating the source database. Run a dry run first:

```bash
oversight-registry \
  --db /var/lib/oversight/rust-registry.sqlite \
  --migrate-from /var/lib/oversight/python-registry.sqlite \
  --migrate-dry-run
```

The command prints JSON row counts for `manifests`, `beacons`, `watermarks`,
`events`, and `corpus`. If the counts are expected, run the same command
without `--migrate-dry-run`:

```bash
oversight-registry \
  --db /var/lib/oversight/rust-registry.sqlite \
  --migrate-from /var/lib/oversight/python-registry.sqlite
```

The migration copies into the Rust target database after running its schema
migrations. It preserves `events.id`, `events.tlog_index`, corpus `metadata`,
and the manifest/beacon/watermark relationships that evidence bundles depend
on. Validate the copied database before switching traffic:

```bash
oversight-registry \
  --db /var/lib/oversight/rust-registry.sqlite \
  --validate-db
```

The validation command prints JSON counts plus integrity failures for orphaned
beacons, watermarks, events, corpus rows, identity mismatches, malformed
event `extra` JSON, malformed corpus metadata JSON, duplicate or negative
tlog indexes, missing event tlog indexes, event tlog indexes outside the
on-disk tlog size, event rows whose indexed tlog leaf carries unrelated
evidence, malformed manifest JSON, invalid manifest signatures, and
manifest/file ID divergence. Keep the Python database as a rollback artifact
until validation, live conformance, and evidence-bundle checks pass against
the Rust service.

## Rust Registry Burn-In Checklist

Run this checklist before switching production traffic from the Python
reference registry to the Rust Axum registry:

1. Take a cold copy of the Python SQLite database and keep the original
   mounted read-only during migration testing.
2. Run `--migrate-dry-run` and compare all row counts against the source
   database.
3. Run the real `--migrate-from` into a fresh Rust database.
4. Run `--validate-db` and treat any nonzero field as a deployment blocker.
5. Start the Rust registry on loopback with `OVERSIGHT_OPERATOR_TOKEN` and
   `OVERSIGHT_DNS_EVENT_SECRET` set.
6. Run the live registry v1 conformance harness against the Rust endpoint.
7. Fetch `/.well-known/oversight-registry`, `/tlog/head`, and at least one
   `/evidence/{file_id}` bundle, then verify the evidence bundle with an
   independent client.
8. Keep the Python database and tlog as rollback artifacts until the Rust
   service has completed the operator's burn-in window.

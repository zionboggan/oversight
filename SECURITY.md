# Security Policy

## Reporting a Vulnerability

Do not open a public GitHub issue for a suspected vulnerability.

Preferred channels, in order:

1. **GitHub Security Advisories.** Use the "Report a vulnerability" button on
   the Security tab of `github.com/oversight-protocol/oversight`. The report is
   private to the maintainers and feeds the coordinated disclosure workflow.
2. **Email.** `zionboggan@gmail.com` with `[Oversight disclosure]` in the
   subject line, as a fallback if the Security tab is unavailable.

Include in the report:

- the affected component (`oversight_core`, the specific `oversight-rust`
  crate, the FastAPI or Axum registry, the CLI, or a deployment artifact);
- a minimal reproduction or proof of concept;
- the version tag or commit you tested against;
- your assessment of impact and any exploit prerequisites.

## Response

Reports are acknowledged within 5 business days. A preliminary assessment
follows within 14 days. Coordinated disclosure timing is decided per report
based on severity and fix complexity. Reporters are credited in the release
advisory unless they ask to remain unnamed.

## Scope

**In scope:**

- the protocol code: `oversight_core` (Python reference), the `oversight-rust`
  workspace, both registry implementations (FastAPI and Axum), and the CLI;
- the `.sealed` container format, manifest signing, the transparency log, and
  the Python to Rust cross-language conformance guarantees;
- the deployment artifacts shipped in this repository (`Dockerfile`,
  `docker-compose.yml`, `Caddyfile`).

**Out of scope:**

- vulnerabilities in third-party dependencies, which belong upstream;
- self-hosted deployments that modified the shipped config;
- attacks that require already compromising the operator account, the registry
  identity key, or a recipient private key.

## Security Design Notes

The honest threat model, watermark layer limits, beacon guarantees, collusion
caveats, and policy boundary notes live in `docs/security.md`. Read that
document before relying on any single attribution signal. Oversight's
attribution layers are forensic evidence, not proof.

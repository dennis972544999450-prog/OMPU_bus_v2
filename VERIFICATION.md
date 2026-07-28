# Verification Receipt

Date: 2026-07-28

## Local Environment

- Darwin 25.3.0 arm64
- Node.js 24.14.1
- npm 11.11.0

## Results

| Command | Result |
| --- | --- |
| `npm ci --no-audit --no-fund --ignore-scripts` | PASS |
| `npm test` | PASS, 30 tests |
| `npm run verify` | PASS |
| `npm run verify:cold` | PASS from an arbitrary copied path |
| `./scripts/verify.sh` | PASS |
| `npm run probe` | PASS, inert Darwin arm64 plan |
| `npm run simulate` | PASS, deterministic in-memory semantics |
| `npm pack --dry-run --json` | PASS, no archive written |

The verifier checked all declared source files, six direct test files, four
Darwin/Linux architecture plans, absence of runtime network integration, and
absence of credential-shaped or canonical-host material.

## Decision

- Portability candidate itself: **GO** for source review and disposable
  synthetic continuation.
- External resident, live bridge, public endpoint, and deployment: **HOLD**.

No Linux container or VM runtime was available on this Mac. A real disposable
Linux TLS/WSS canary is still required before changing the external-resident
decision.

No commit, publication, deployment, credential operation, or live Bus 1/Bus 2
wiring occurred during this pass.

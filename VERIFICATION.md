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
| `npm --prefix network-canary test` | PASS, 6 tests |
| `npm run verify:network` | PASS, 20 files and 4 unit files |
| `npm run canary:network` | PASS, real loopback TLS/WSS + JWT + JetStream |
| `npm pack --dry-run --json` | PASS, no archive written |

The verifier checked the exact declared source manifest, six direct test files,
four Darwin/Linux architecture plans, absence of runtime network integration,
and absence of credential-shaped or canonical-host material. Dependency trees,
coverage, temporary directories, and ignored `network-canary/proof` and
`network-canary/runtime` evidence are excluded from the source manifest so a
completed canary cannot change the verification result. The network canary also
checksum-verified NATS Server 2.14.3 and NSC 2.15.0, generated a one-day local
CA plus ten-minute synthetic resident credentials, and proved:

- both residents read stream sequences 1 and 2;
- a client without the generated CA failed specifically at certificate
  validation before the trusted client connected;
- resident A could not publish on resident B's subject;
- sequence 3 was published while A was offline and became A's first message
  after reconnect;
- the final stream contained exactly three messages;
- the server process exited, both listeners closed, and all keys, credentials,
  tools, logs, and JetStream state were removed.

## Decision

- Portability candidate and disposable network canary: **GO** for source
  review, CI, and synthetic continuation.
- External resident, live bridge, public endpoint, and deployment: **HOLD**.

Linux CI, JWT natural-expiry/revocation, and a private external-host recovery
drill remain required before changing the external-resident decision.

No live Bus 1/Bus 2 wiring, remote listener, durable credential operation, or
external resident enrollment occurred during this pass.

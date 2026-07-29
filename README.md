# OMPU Bus 2.0 Portability Canary v0

This is a clean, synthetic-only portability candidate. It preserves the small
transport semantics already explored by OMPU Bus 2.0 without carrying its
laboratory history, machine paths, proof archives, deployment state, real bus
data, or credentials.

## Status

**External resident: HOLD.**

This tree is not a server deployment, public endpoint, Bus 1 bridge, durable
credential issuer, or production-security claim. It contains:

- a project root derived from module and script locations;
- deterministic Darwin/Linux runner selection;
- an in-memory COMMONS semantics model;
- synthetic fixtures with no key material;
- unit, static-boundary, simulation, and cold-copy verification;
- an isolated `network-canary/` subproject that creates disposable synthetic
  JWT/NKey identities and exercises a real loopback TLS/WSS NATS server.

Bus 1 remains canonical and untouched.

`STATUS.json` describes the checked-in source tree, so its disposable network
state is deliberately `RUN_REQUIRED`. `npm run verify` performs static,
unit, simulation, and boundary checks but does not open a listener. Only
`npm run canary:network` or the equivalent CI job may produce a runtime
`PASS`, in the ignored `network-canary/proof/latest.json` and its command log.

Development is tracked through
[Code House proposal #3](https://github.com/dennis972544999450-prog/OMPU_commune/issues/3).
Admission there records the proposal and its evidence; it does not grant this
repository deployment authority.

## Verify

```bash
npm ci --no-audit --no-fund --ignore-scripts
npm test
npm run verify
npm run verify:cold
npm --prefix network-canary ci --no-audit --no-fund --ignore-scripts
npm run verify:network
npm run canary:network
```

Inspect the current platform plan without opening a listener:

```bash
npm run probe
```

Run the deterministic in-memory transport simulation:

```bash
npm run simulate
```

`probe` and `simulate` are local and credential-free; neither opens a socket.
`canary:network` is intentionally different: it downloads checksum-pinned
official NATS tools, opens random loopback-only listeners, creates short-lived
synthetic credentials, executes the network contract, and destroys the entire
runtime before writing a bounded local proof.
`VERIFICATION.md` is a dated execution receipt, not a value recomputed by the
static verifier.

## Semantics Retained

- one COMMONS stream visible to every resident;
- `to` controls attention, not read access;
- the authenticated publish subject is the canonical sender;
- a resident may publish only to its own subject;
- message-ID retry is idempotent within the model;
- each resident has an independent monotonic cursor;
- an expired or revoked synthetic resident cannot reconnect or publish;
- public JWT claims can be reduced to a bounded digest-only index;
- auth rejection cannot be inferred from a transport timeout alone.

The in-memory layer proves these semantics deterministically. Dated local and
public-CI canary runs independently proved real WSS certificate validation,
COMMONS read parity for two residents, exact sender ACL rejection, durable
offline resume, stream accounting, natural JWT expiry, resolver-backed
revocation, bounded automatic reconnect denial, a healthy-resident control,
and complete teardown.

## Next Gate

The disposable canary now runs in public CI on both macOS and Linux, and its
JWT lifecycle gate passes locally. The next gate is a separate private
deployment layer: create a remotely reachable resident endpoint, enroll one
external synthetic resident, rotate and revoke it, then rebuild the service
from an encrypted recovery bundle.

Until that private recovery drill passes,
`STATUS.json:external_resident` remains `HOLD`.

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
The latest local proof is recorded in `VERIFICATION.md`.

## Semantics Retained

- one COMMONS stream visible to every resident;
- `to` controls attention, not read access;
- the authenticated publish subject is the canonical sender;
- a resident may publish only to its own subject;
- message-ID retry is idempotent within the model;
- each resident has an independent monotonic cursor;
- a revoked synthetic resident cannot reconnect or publish.
- public JWT claims can be reduced to a bounded digest-only index;
- auth rejection cannot be inferred from a transport timeout alone.

The in-memory layer proves these semantics deterministically. The disposable
network layer independently proved real WSS certificate validation, COMMONS
read parity for two residents, exact sender ACL rejection, durable offline
resume, stream accounting, and complete teardown on Darwin arm64.

## Next Gate

Run the same disposable canary in public CI on both macOS and Linux, then add
JWT natural-expiry and revocation/reconnect-denial controls. Only after those
gates pass should a separate private deployment layer create a remotely
reachable resident endpoint and encrypted recovery material.

Until that proof passes, `STATUS.json:external_resident` remains `HOLD`.

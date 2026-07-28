# OMPU Bus 2.0 Portability Canary v0

This is a clean, synthetic-only portability candidate. It preserves the small
transport semantics already explored by OMPU Bus 2.0 without carrying its
laboratory history, machine paths, proof archives, deployment state, real bus
data, or credentials.

## Status

**External resident: HOLD.**

This tree is not a server deployment, resident client, public endpoint, Bus 1
bridge, credential issuer, or production-security claim. It contains:

- a project root derived from module and script locations;
- deterministic Darwin/Linux runner selection;
- an in-memory COMMONS semantics model;
- synthetic fixtures with no key material;
- unit, static-boundary, simulation, and cold-copy verification;
- an explicit next gate for a real disposable Linux TLS/WSS canary.

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
```

Inspect the current platform plan without opening a listener:

```bash
npm run probe
```

Run the deterministic in-memory transport simulation:

```bash
npm run simulate
```

Both commands are local and credential-free. Neither opens a socket.
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

These are executable unit semantics, not network evidence.

## Next Gate

Build and run one disposable macOS-to-Linux TLS/WSS canary using synthetic
identities. It must prove certificate validation, COMMONS read/write parity,
durable offline resume, exact subject ACLs, revocation/reconnect denial, and
complete teardown across a real Linux boundary.

Until that proof passes, `STATUS.json:external_resident` remains `HOLD`.

# Provenance

Date: 2026-07-28

This tree is a clean implementation of a bounded portability candidate. Its
behavioral requirements were derived from the local OMPU Bus 2.0 architecture
and synthetic canary contracts, especially:

- address and audience are independent;
- every resident reads COMMONS;
- publish subjects authorize canonical sender identity;
- retries are bounded and idempotent;
- resident cursors resume monotonically;
- external Linux TLS/WSS remains an unclosed gate.

No proof archive, runtime state, real message, credential, NATS configuration,
private mapping, vendored dependency tree, or source history was copied.
Implementation code in this directory was written for this candidate rather
than copied byte-for-byte from the laboratory tree.

The bounded derivation is explicit:

- `src/jwt-evidence.mjs` independently reimplements public-claim indexing,
  redaction, and auth-versus-transport evidence classification from the current
  JWT canary concepts;
- `src/synthetic-transport.mjs` implements the accepted COMMONS, sender ACL,
  idempotency, cursor, and revocation semantics without a broker;
- runner modules replace the former machine-bound shell wrapper with inert
  Darwin/Linux plans. They do not execute NATS or generate credentials.

## Deliberate Behavioral Correction

The laboratory redactor replaces NATS URL userinfo with a marker that still
appears as userinfo to its own secret scanner. A deterministic candidate test
caught that mismatch. This implementation removes URL userinfo completely, so
redacted output is also clean under the scanner. The divergence is intentional
and covered by `test/jwt-evidence.test.mjs`.

## Open Provenance Concern

The source laboratory directory is not currently a git repository and does not
carry an explicit license. Therefore this candidate must not claim an upstream
commit hash or inherit an upstream license by implication. Before public
distribution, an OMPU maintainer should confirm the intended license and
attribution. The included MIT text applies only to newly authored material in
this candidate unless that confirmation broadens the scope.

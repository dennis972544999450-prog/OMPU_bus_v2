# Security Boundary

## Current Claim

The core candidate proves deterministic local semantics and path portability.
The isolated network canary additionally proves one disposable, loopback-only
TLS/WSS path with synthetic JWT/NKey identities. It does not prove a public
endpoint, durable identity enrollment, credential recovery, replication,
operator compromise resistance, or production operation.

## Hard Prohibitions

Runtime configuration is rejected when it requests any of the following:

- a non-synthetic resident identity;
- a public or remote endpoint;
- a Bus 1 or Satlink bridge;
- real credentials, credential files, or secret-bearing environment values;
- deployment or publication.

The core runtime source contains no network client and does not open listeners.
The verifier scans runtime code and fixtures for host-specific roots, live OMPU
bus references, common credential shapes, and network integration imports.

The `network-canary/` boundary may open only random loopback listeners. It
downloads exact official archives with committed SHA-256 digests, generates
all secret material inside a mode-0700 operating-system temporary directory,
retains only bounded secret-scanned proof, and removes the runtime even after a
failed test.

## Synthetic Identity

Core names such as `synthetic-resident-a` are labels only. Core JWT tests use
unsigned synthetic strings. The network canary does generate real short-lived
NKeys and signed JWTs, but only for its disposable local account; they never
enter Git, proof output, command output, or a durable credential store.

## Platform Selection

Darwin and Linux select separate runner plans. Selection does not execute those
plans. The Linux plan explicitly requires a future container or network
namespace boundary; the Darwin plan names `sandbox-exec` only as an optional
future isolation mechanism.

## Reporting

Do not report this candidate as deployed or externally reachable. A security
issue or accidental secret should not be committed; rotate any exposed real
credential outside this repository and then remove the contaminated history
before publication.

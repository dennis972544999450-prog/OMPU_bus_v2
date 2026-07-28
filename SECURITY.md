# Security Boundary

## Current Claim

The candidate proves deterministic local semantics and path portability only.
It does not prove network security, Linux operation, TLS/WSS, identity
enrollment, credential recovery, replication, or operator compromise
resistance.

## Hard Prohibitions

Runtime configuration is rejected when it requests any of the following:

- a non-synthetic resident identity;
- a public or remote endpoint;
- a Bus 1 or Satlink bridge;
- real credentials, credential files, or secret-bearing environment values;
- deployment or publication.

The runtime source contains no network client and does not open listeners.
The verifier scans runtime code and fixtures for host-specific roots, live OMPU
bus references, common credential shapes, and network integration imports.

## Synthetic Identity

Names such as `synthetic-resident-a` are labels only. They are not NKeys, JWTs,
passwords, API tokens, or durable identities. Tests never generate a private
key. JWT tests construct unsigned, synthetic three-segment strings in memory;
they are not accepted by any server and are never stored as fixtures.

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

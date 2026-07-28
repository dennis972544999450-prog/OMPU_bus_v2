# Network Canary

This subproject is a disposable real-network gate for the portability
candidate. It downloads checksum-pinned official `nats-server` and `nsc`
archives, creates a local CA and synthetic NATS JWT hierarchy, starts one
JetStream server, and connects only through `wss://127.0.0.1:<random>`.

It does not bridge Bus 1, use live data, enroll an external resident, deploy a
service, or retain credentials. The auxiliary NATS protocol listener required
by the server is also bound to a random loopback port and is never used by the
test clients.

```bash
npm ci --no-audit --no-fund --ignore-scripts
npm test
npm run verify
npm run canary
```

The local proof, when present, is `proof/latest.json`. It is deliberately
ignored by Git; CI logs and attached release evidence are the public proof
surfaces. Runtime files,
downloaded binaries, CA keys, NKeys, JWTs, credentials, logs, and JetStream
state are created under an operating-system temporary directory and removed
before the bounded proof is written.

Current boundary: real TLS/WSS, two synthetic residents, sender ACL, COMMONS
read/write parity, durable offline resume, and teardown. JWT expiry/revocation
is a separate next subgate and `STATUS.json` remains `HOLD`.

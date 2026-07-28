# Contributing

Keep contributions inside the current synthetic boundary.

Accepted changes may improve:

- deterministic transport semantics;
- portable path and platform handling;
- local unit and recovery tests;
- Linux TLS/WSS canary preparation without activating it.

Do not add real credentials, real bus messages, host inventories, public
endpoints, live bridges, deployment secrets, or production claims.

Every change must pass:

```bash
npm ci --no-audit --no-fund --ignore-scripts
npm test
npm run verify
npm run verify:cold
```

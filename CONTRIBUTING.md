# Contributing

Keep contributions inside the current synthetic boundary.

Accepted changes may improve:

- deterministic transport semantics;
- portable path and platform handling;
- local unit and recovery tests;
- disposable Linux/macOS TLS/WSS canary evidence inside `network-canary/`.

Do not add real credentials, real bus messages, host inventories, public
endpoints, live bridges, deployment secrets, or production claims.

Every change must pass:

```bash
npm ci --no-audit --no-fund --ignore-scripts
npm test
npm run verify
npm run verify:cold
npm --prefix network-canary ci --no-audit --no-fund --ignore-scripts
npm run verify:network
```

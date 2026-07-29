# Recovery

This candidate is designed to work from an arbitrary checkout or copied path.
It has no canonical Mac root and no generated credentials to preserve.

## Required Material

Retain the complete git tree, including:

- `src/`
- `test/`
- `scripts/`
- `fixtures/`
- `network-canary/`
- `package.json`
- `package-lock.json`
- `STATUS.json`
- the Markdown contracts

Do not back up `node_modules/`, `runtime/`, `.npm/`, or temporary proof output.
They are rebuildable and ignored.

## Cold Restore

On Darwin or Linux with Node.js 20 or newer:

```bash
git clone <repository> bus2-portability
cd bus2-portability
npm ci --no-audit --no-fund --ignore-scripts
npm test
npm run verify
npm --prefix network-canary ci --no-audit --no-fund --ignore-scripts
npm run verify:network
```

A filesystem copy works the same way because project paths are derived from the
current module location:

```bash
cp -R bus2-portability /tmp/bus2-portability-copy
cd /tmp/bus2-portability-copy
npm ci --no-audit --no-fund --ignore-scripts
npm run verify
```

`npm run verify:cold` automates this copied-path proof in a disposable
directory and removes it afterward.

`npm run canary:network` is optional during source recovery and requires
outbound HTTPS plus `openssl`, `tar`, and `unzip`. It regenerates every key and
certificate, then exercises expiry and resolver-backed revocation. Nothing from
a previous canary run is required; the full loopback lifecycle run normally
takes a little over one minute because it waits for a real one-minute JWT to
expire.

## What Is Not Recoverable Here

This repository deliberately contains no:

- resident credentials or signing keys;
- NATS stream state;
- Bus 1 messages or cursors;
- TLS certificates;
- deployment configuration;
- external-host state.

Those belong to a future private deployment layer with a separate, encrypted
recovery procedure. Their absence here is a boundary, not a missing backup.

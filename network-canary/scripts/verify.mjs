import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  lstatSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import path from "node:path";

import { NETWORK_ROOT, resolveNetworkPath } from "../src/paths.mjs";
import { secretFindings } from "../src/safety.mjs";
import { validateToolchainManifest } from "../src/toolchain.mjs";

const REQUIRED = [
  "README.md",
  "STATUS.json",
  "package-lock.json",
  "package.json",
  "scripts/run-network-canary.mjs",
  "scripts/lifecycle-client.mjs",
  "scripts/verify.mjs",
  "scripts/wss-client.mjs",
  "src/certificates.mjs",
  "src/contracts.mjs",
  "src/identity.mjs",
  "src/lifecycle-evidence.mjs",
  "src/paths.mjs",
  "src/runtime.mjs",
  "src/safety.mjs",
  "src/toolchain.mjs",
  "test/contracts.test.mjs",
  "test/lifecycle-evidence.test.mjs",
  "test/paths.test.mjs",
  "test/runtime.test.mjs",
  "test/safety.test.mjs",
  "test/toolchain.test.mjs",
  "toolchain.json",
];

function walk(directory) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === "proof") {
      continue;
    }
    const absolute = path.join(directory, entry.name);
    if (lstatSync(absolute).isSymbolicLink()) {
      throw new Error(`symlink forbidden: ${absolute}`);
    }
    if (entry.isDirectory()) {
      files.push(...walk(absolute));
    } else if (entry.isFile()) {
      files.push(path.relative(NETWORK_ROOT, absolute));
    }
  }
  return files;
}

const files = walk(NETWORK_ROOT).sort();
for (const required of REQUIRED) {
  assert.equal(files.includes(required), true, `missing ${required}`);
}

const packageJson = JSON.parse(
  readFileSync(resolveNetworkPath("package.json"), "utf8"),
);
assert.deepEqual(packageJson.engines, { node: "24.x" });
assert.deepEqual(packageJson.dependencies, {
  "@nats-io/jetstream": "3.4.0",
  "@nats-io/nats-core": "3.4.0",
});

const status = JSON.parse(
  readFileSync(resolveNetworkPath("STATUS.json"), "utf8"),
);
assert.equal(status.external_resident, "HOLD");
assert.equal(status.synthetic_only, true);
assert.equal(status.loopback_only, true);
assert.equal(status.public_endpoint, false);
assert.equal(status.live_bus_bridge, false);
assert.equal(status.retained_credentials, false);
assert.equal(status.runtime_canary, "RUN_REQUIRED");
assert.equal(status.runtime_proof_path, "proof/latest.json");
assert.equal(status.runtime_proof_committed, false);

validateToolchainManifest();

for (const file of files) {
  const text = readFileSync(resolveNetworkPath(file), "utf8");
  assert.equal(text.includes("/" + "Users" + "/"), false, `host path in ${file}`);
  assert.deepEqual(secretFindings(text), [], `secret-shaped text in ${file}`);
}

const tests = files
  .filter((file) => /^test\/[^/]+\.test\.mjs$/.test(file))
  .map((file) => resolveNetworkPath(file));
assert.equal(tests.length, 6);
const result = spawnSync(process.execPath, ["--test", ...tests], {
  cwd: NETWORK_ROOT,
  encoding: "utf8",
});
if (result.status !== 0) {
  process.stderr.write(result.stdout);
  process.stderr.write(result.stderr);
  throw new Error("network-canary unit tests failed");
}

console.log(
  JSON.stringify(
    {
      schema: "ompu.bus2.network-static-verification.v0.1",
      status: "PASS",
      files_checked: files.length,
      unit_files: tests.length,
      real_network_executed: false,
    },
    null,
    2,
  ),
);

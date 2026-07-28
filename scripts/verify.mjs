import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  lstatSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import path from "node:path";

import { PROJECT_ROOT, resolveInsideProject } from "../src/project-root.mjs";
import { buildRunnerPlan } from "../src/runner.mjs";
import { runSimulation } from "../src/simulation.mjs";

const REQUIRED_FILES = Object.freeze([
  ".github/workflows/ci.yml",
  ".gitignore",
  "CONTRIBUTING.md",
  "LICENSE",
  "network-canary/.gitignore",
  "network-canary/README.md",
  "network-canary/STATUS.json",
  "network-canary/package-lock.json",
  "network-canary/package.json",
  "network-canary/scripts/run-network-canary.mjs",
  "network-canary/scripts/verify.mjs",
  "network-canary/scripts/wss-client.mjs",
  "network-canary/src/certificates.mjs",
  "network-canary/src/contracts.mjs",
  "network-canary/src/identity.mjs",
  "network-canary/src/paths.mjs",
  "network-canary/src/runtime.mjs",
  "network-canary/src/safety.mjs",
  "network-canary/src/toolchain.mjs",
  "network-canary/test/contracts.test.mjs",
  "network-canary/test/paths.test.mjs",
  "network-canary/test/safety.test.mjs",
  "network-canary/test/toolchain.test.mjs",
  "network-canary/toolchain.json",
  "PROVENANCE.md",
  "README.md",
  "RECOVERY.md",
  "SECURITY.md",
  "STATUS.json",
  "VERIFICATION.md",
  "fixtures/events.jsonl",
  "fixtures/transport.json",
  "package-lock.json",
  "package.json",
  "scripts/cold-copy-verify.mjs",
  "scripts/verify.mjs",
  "scripts/verify.sh",
  "src/cli.mjs",
  "src/event.mjs",
  "src/fixtures.mjs",
  "src/jwt-evidence.mjs",
  "src/platform.mjs",
  "src/project-root.mjs",
  "src/runner.mjs",
  "src/runners/darwin.mjs",
  "src/runners/linux.mjs",
  "src/security-boundary.mjs",
  "src/simulation.mjs",
  "src/synthetic-transport.mjs",
  "test/cli.test.mjs",
  "test/jwt-evidence.test.mjs",
  "test/platform.test.mjs",
  "test/project-root.test.mjs",
  "test/security-boundary.test.mjs",
  "test/synthetic-transport.test.mjs",
]);

const GENERATED_DIRECTORIES = new Set([
  ".npm",
  ".tmp",
  "coverage",
  "network-canary/proof",
  "network-canary/runtime",
]);

function walk(directory) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    const relative = path.relative(PROJECT_ROOT, absolute);
    if (lstatSync(absolute).isSymbolicLink()) {
      throw new Error(`symlink is forbidden: ${relative}`);
    }
    if (
      entry.isDirectory()
      && (
        entry.name === ".git"
        || entry.name === "node_modules"
        || GENERATED_DIRECTORIES.has(relative)
      )
    ) {
      continue;
    }
    if (entry.isDirectory()) {
      files.push(...walk(absolute));
    } else if (entry.isFile()) {
      files.push(relative);
    }
  }
  return files;
}

function read(relativePath) {
  return readFileSync(resolveInsideProject(relativePath), "utf8");
}

function assertNoHostOrLiveMaterial(files) {
  const forbiddenText = [
    ["/" + "Users" + "/denbell", "canonical user root"],
    ["/opt/" + "homebrew", "Homebrew installation root"],
    ["OMPU_" + "shared/bus", "live Bus 1 path"],
    ["bus_v2/" + "runtime", "source laboratory runtime"],
  ];
  const credentialShapes = [
    new RegExp("\\bS[A-Z2-7]{55}\\b"),
    new RegExp("-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----"),
    new RegExp("\\bgh[pousr]_[A-Za-z0-9]{20,}\\b"),
    new RegExp("\\bgithub_pat_[A-Za-z0-9_]{20,}\\b"),
  ];

  for (const file of files) {
    const content = read(file);
    for (const [needle, label] of forbiddenText) {
      assert.equal(content.includes(needle), false, `${label} in ${file}`);
    }
    for (const pattern of credentialShapes) {
      assert.equal(pattern.test(content), false, `credential shape in ${file}`);
    }
  }
}

function assertRuntimeHasNoNetworkIntegration(files) {
  const forbiddenRuntimeText = [
    "node:" + "net",
    "node:" + "tls",
    "node:" + "http",
    "node:" + "https",
    "fetch" + "(",
    "new " + "WebSocket",
    "nats." + "connect",
  ];

  for (const file of files.filter((candidate) => candidate.startsWith("src/"))) {
    const content = read(file);
    for (const needle of forbiddenRuntimeText) {
      assert.equal(
        content.includes(needle),
        false,
        `network integration marker ${needle} in ${file}`,
      );
    }
  }
}

function runUnitTests(testFiles) {
  const result = spawnSync(
    process.execPath,
    ["--test", ...testFiles.map((file) => resolveInsideProject(file))],
    {
      cwd: PROJECT_ROOT,
      encoding: "utf8",
      env: { ...process.env },
    },
  );
  if (result.status !== 0) {
    process.stderr.write(result.stdout);
    process.stderr.write(result.stderr);
    throw new Error(`unit tests failed with status ${result.status}`);
  }
  return result.stdout;
}

const files = walk(PROJECT_ROOT).sort();
assert.deepEqual(files, [...REQUIRED_FILES].sort(), "source manifest drift");

const packageJson = JSON.parse(read("package.json"));
assert.equal(packageJson.scripts.test, "node --test test/*.test.mjs");
assert.equal(packageJson.type, "module");
assert.equal(Object.keys(packageJson.dependencies || {}).length, 0);
assert.equal(Object.keys(packageJson.devDependencies || {}).length, 0);

const status = JSON.parse(read("STATUS.json"));
assert.equal(status.external_resident, "HOLD");
assert.equal(status.live_bus_bridge, false);
assert.equal(status.public_endpoint, false);
assert.equal(status.real_credentials, false);
assert.equal(status.network_integration, false);
assert.equal(status.disposable_network_canary, "PASS");

assertNoHostOrLiveMaterial(files);
assertRuntimeHasNoNetworkIntegration(files);

const testFiles = files
  .filter((file) => /^test\/[^/]+\.test\.mjs$/.test(file))
  .sort();
assert.equal(testFiles.length, 6);
runUnitTests(testFiles);

const simulation = runSimulation();
assert.equal(simulation.status, "PASS");
assert.equal(simulation.externalResident, "HOLD");
assert.equal(
  Object.entries(simulation)
    .filter(([key]) => !["schema", "status", "externalResident", "storedSequences"].includes(key))
    .every(([, value]) => value === true),
  true,
);

for (const target of [
  { platform: "darwin", arch: "arm64" },
  { platform: "darwin", arch: "x64" },
  { platform: "linux", arch: "arm64" },
  { platform: "linux", arch: "x64" },
]) {
  const plan = await buildRunnerPlan({ ...target, env: {} });
  assert.equal(plan.execution, "plan-only");
  assert.equal(plan.network.mode, "disabled");
  assert.equal(plan.externalResident, "HOLD");
}

console.log(
  JSON.stringify(
    {
      schema: "ompu.bus2.portability-verification.v0.1",
      status: "PASS",
      externalResident: "HOLD",
      filesChecked: files.length,
      unitFiles: testFiles.length,
      runnerPlansChecked: 4,
      networkIntegration: false,
      credentialsPresent: false,
    },
    null,
    2,
  ),
);

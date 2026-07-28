import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { PROJECT_ROOT } from "../src/project-root.mjs";

function runCli(command) {
  const result = spawnSync(process.execPath, ["src/cli.mjs", command], {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
    env: { ...process.env },
  });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("probe returns an inert current-platform plan", () => {
  const probe = runCli("probe");
  assert.equal(probe.execution, "plan-only");
  assert.equal(probe.network.mode, "disabled");
  assert.equal(probe.network.listener, null);
  assert.equal(probe.externalResident, "HOLD");
});

test("simulate command returns the deterministic proof surface", () => {
  const simulation = runCli("simulate");
  assert.equal(simulation.status, "PASS");
  assert.equal(simulation.externalResident, "HOLD");
  assert.equal(simulation.allResidentsSawFirst, true);
  assert.equal(simulation.revokedReconnectDenied, true);
});

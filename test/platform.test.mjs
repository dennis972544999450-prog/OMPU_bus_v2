import assert from "node:assert/strict";
import test from "node:test";

import { selectPlatform, supportedTargets } from "../src/platform.mjs";
import { buildRunnerPlan } from "../src/runner.mjs";

test("supported target matrix is explicit and stable", () => {
  assert.deepEqual(supportedTargets(), [
    "darwin-arm64",
    "darwin-x64",
    "linux-arm64",
    "linux-x64",
  ]);
});

test("Darwin arm64 selects the Darwin runner without host paths", () => {
  const selected = selectPlatform({
    platform: "darwin",
    arch: "arm64",
    env: {},
  });
  assert.equal(selected.runner, "darwin");
  assert.equal(selected.nscAsset, "nsc-darwin-arm64.zip");
  assert.deepEqual(selected.executables, {
    natsServer: "nats-server",
    nsc: "nsc",
  });
});

test("Linux x64 selects the Linux isolation requirement", () => {
  const selected = selectPlatform({
    platform: "linux",
    arch: "x64",
    env: {},
  });
  assert.equal(selected.runner, "linux");
  assert.equal(selected.nscAsset, "nsc-linux-amd64.zip");
  assert.equal(
    selected.isolation,
    "container-or-network-namespace-required",
  );
});

test("executable overrides are data, not hardcoded platform paths", () => {
  const selected = selectPlatform({
    platform: "linux",
    arch: "arm64",
    env: {
      OMPU_NATS_SERVER: "/custom/bin/nats-server",
      OMPU_NSC: "/custom/bin/nsc",
    },
  });
  assert.equal(selected.executables.natsServer, "/custom/bin/nats-server");
  assert.equal(selected.executables.nsc, "/custom/bin/nsc");
});

test("unsupported targets fail closed", () => {
  assert.throws(
    () => selectPlatform({ platform: "win32", arch: "x64", env: {} }),
    (error) => error.code === "UNSUPPORTED_PLATFORM",
  );
});

test("runner plans are inert on both Darwin and Linux", async () => {
  for (const platform of ["darwin", "linux"]) {
    const plan = await buildRunnerPlan({ platform, arch: "x64", env: {} });
    assert.equal(plan.execution, "plan-only");
    assert.equal(plan.network.mode, "disabled");
    assert.equal(plan.network.listener, null);
    assert.equal(plan.syntheticOnly, true);
    assert.equal(plan.externalResident, "HOLD");
    assert.match(plan.runner, new RegExp(`^${platform}-`));
  }
});

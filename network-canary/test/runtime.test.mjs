import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import test from "node:test";

import { waitForProcessExit } from "../src/runtime.mjs";

test("process wait clears its losing timeout branch", async () => {
  const child = spawn(process.execPath, ["-e", "process.exit(0)"], {
    stdio: "ignore",
  });
  const started = Date.now();
  assert.equal(await waitForProcessExit(child, 5_000), true);
  assert.ok(Date.now() - started < 1_000);
});

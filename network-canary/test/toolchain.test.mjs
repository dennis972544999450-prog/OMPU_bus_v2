import assert from "node:assert/strict";
import test from "node:test";

import {
  selectToolchain,
  validateToolchainManifest,
} from "../src/toolchain.mjs";

test("toolchain manifest is complete and pinned", () => {
  assert.equal(validateToolchainManifest(), true);
  for (const target of [
    ["darwin", "arm64"],
    ["darwin", "x64"],
    ["linux", "arm64"],
    ["linux", "x64"],
  ]) {
    const selected = selectToolchain({
      platform: target[0],
      arch: target[1],
    });
    assert.equal(selected.natsServerVersion, "2.14.3");
    assert.equal(selected.nscVersion, "2.15.0");
  }
});

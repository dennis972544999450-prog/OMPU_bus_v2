import assert from "node:assert/strict";
import test from "node:test";

import {
  assertSecretFree,
  redactSensitiveText,
  secretFindings,
} from "../src/safety.mjs";

test("ordinary proof data is accepted", () => {
  assert.deepEqual(secretFindings({ status: "PASS", sequence: 3 }), []);
  assert.doesNotThrow(() => assertSecretFree({ status: "PASS" }));
});

test("constructed seed-shaped material is rejected and redacted", () => {
  const candidate = ["S", "A".repeat(55)].join("");
  assert.deepEqual(secretFindings(candidate), ["nkey-seed"]);
  assert.equal(redactSensitiveText(candidate), "<redacted-seed>");
});

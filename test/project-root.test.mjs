import assert from "node:assert/strict";
import { existsSync, realpathSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  PROJECT_ROOT,
  assertInsideProject,
  resolveInsideProject,
} from "../src/project-root.mjs";

test("project root is derived from the checked-out module tree", () => {
  const testDir = path.dirname(fileURLToPath(import.meta.url));
  const expected = realpathSync(path.resolve(testDir, ".."));
  assert.equal(PROJECT_ROOT, expected);
  assert.equal(existsSync(path.join(PROJECT_ROOT, "package.json")), true);
});

test("project-relative paths resolve inside the current copy", () => {
  const fixture = resolveInsideProject("fixtures", "transport.json");
  assert.equal(fixture.startsWith(`${PROJECT_ROOT}${path.sep}`), true);
  assert.equal(existsSync(fixture), true);
});

test("paths outside the current copy are rejected", () => {
  const outside = path.resolve(PROJECT_ROOT, "..", "outside.txt");
  assert.throws(
    () => assertInsideProject(outside),
    (error) => error.code === "OUTSIDE_PROJECT",
  );
});

import assert from "node:assert/strict";
import test from "node:test";

import { NETWORK_ROOT, resolveNetworkPath } from "../src/paths.mjs";

test("network paths stay inside the subproject", () => {
  assert.equal(resolveNetworkPath("src").startsWith(NETWORK_ROOT), true);
  assert.throws(
    () => resolveNetworkPath("..", "outside"),
    { code: "NETWORK_PATH_ESCAPE" },
  );
});

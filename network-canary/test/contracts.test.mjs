import assert from "node:assert/strict";
import test from "node:test";

import {
  SUBJECT_A,
  SUBJECT_B,
  buildServerConfig,
  userPermissions,
} from "../src/contracts.mjs";

test("resident publish ACLs are disjoint", () => {
  const a = userPermissions("a");
  const b = userPermissions("b");
  assert.equal(a.pub.includes(SUBJECT_A), true);
  assert.equal(a.pub.includes(SUBJECT_B), false);
  assert.equal(b.pub.includes(SUBJECT_B), true);
  assert.equal(b.pub.includes(SUBJECT_A), false);
});

test("server config binds both transports to loopback", () => {
  const config = buildServerConfig("operator: synthetic", {
    clientPort: 4223,
    wssPort: 9443,
    certFile: "/tmp/server.pem",
    keyFile: "/tmp/server.key",
    storeDir: "/tmp/store",
  });
  assert.match(config, /127\.0\.0\.1:4223/);
  assert.match(config, /127\.0\.0\.1:9443/);
  assert.match(config, /no_tls: false/);
});

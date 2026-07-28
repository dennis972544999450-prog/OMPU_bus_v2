import assert from "node:assert/strict";
import test from "node:test";

import { loadSyntheticBoundary } from "../src/fixtures.mjs";
import {
  assertSyntheticBoundary,
  containsCredentialShape,
  isSyntheticIdentity,
} from "../src/security-boundary.mjs";

test("checked-in boundary is synthetic and inert", () => {
  const boundary = loadSyntheticBoundary();
  assert.equal(boundary.mode, "synthetic-only");
  assert.equal(boundary.endpoint, null);
  assert.equal(boundary.identities.length, 3);
  assert.equal(boundary.identities.every(isSyntheticIdentity), true);
});

test("remote endpoint requests are rejected", () => {
  const boundary = loadSyntheticBoundary();
  assert.throws(
    () =>
      assertSyntheticBoundary({
        ...boundary,
        endpoint: "wss://example.invalid",
      }),
    (error) => error.code === "ENDPOINT_FORBIDDEN",
  );
});

test("bridge, deployment, and real credential switches fail closed", () => {
  const boundary = loadSyntheticBoundary();
  for (const field of ["liveBusBridge", "deploy", "realCredentials"]) {
    assert.throws(
      () => assertSyntheticBoundary({ ...boundary, [field]: true }),
      (error) => error.code === "LIVE_CAPABILITY_FORBIDDEN",
    );
  }
});

test("non-synthetic identities are rejected", () => {
  const boundary = loadSyntheticBoundary();
  assert.throws(
    () =>
      assertSyntheticBoundary({
        ...boundary,
        identities: ["synthetic-resident-a", "resident-real"],
      }),
    (error) => error.code === "IDENTITY_FORBIDDEN",
  );
});

test("unknown fields cannot smuggle credential or deployment configuration", () => {
  const boundary = loadSyntheticBoundary();
  assert.throws(
    () =>
      assertSyntheticBoundary({
        ...boundary,
        credentialFile: "/private/example.creds",
      }),
    (error) => error.code === "BOUNDARY_FIELD_FORBIDDEN",
  );
});

test("credential-shaped values are detected without storing a credential", () => {
  const shaped = ["gh", "p_", "A".repeat(36)].join("");
  assert.equal(containsCredentialShape(shaped), true);
  assert.equal(containsCredentialShape("synthetic-resident-a"), false);
});

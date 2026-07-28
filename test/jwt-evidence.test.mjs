import assert from "node:assert/strict";
import test from "node:test";

import {
  authRejectionProved,
  classifyConnectionFailure,
  decodePublicJwtPayload,
  redactSensitiveText,
  safePublicClaimIndex,
  secretMaterialFindings,
} from "../src/jwt-evidence.mjs";

function syntheticJwt(payload) {
  const header = Buffer.from(JSON.stringify({ alg: "synthetic" })).toString(
    "base64url",
  );
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.synthetic-signature`;
}

test("public JWT claim indexing returns only bounded fields and a digest", () => {
  const jwt = syntheticJwt({
    iss: "synthetic-issuer",
    sub: "synthetic-subject",
    jti: "synthetic-jti",
    iat: 100,
    exp: 200,
    name: "synthetic-resident-a",
    nats: {
      pub: { allow: ["commons.synthetic-resident-a"] },
      sub: { allow: ["commons.>"] },
    },
    ignored_private_extension: "not-indexed",
  });
  const index = safePublicClaimIndex("resident-a", jwt);

  assert.equal(index.jwt_sha256.length, 64);
  assert.equal(index.subject, "synthetic-subject");
  assert.deepEqual(index.publish_allow, ["commons.synthetic-resident-a"]);
  assert.equal(JSON.stringify(index).includes(jwt), false);
  assert.equal("ignored_private_extension" in index, false);
});

test("malformed JWT payloads fail closed", () => {
  assert.throws(
    () => decodePublicJwtPayload("one.two"),
    (error) => error.code === "JWT_SHAPE_INVALID",
  );
  assert.throws(
    () => decodePublicJwtPayload("e30.bm90LWpzb24.synthetic"),
    (error) => error.code === "JWT_PAYLOAD_INVALID",
  );
});

test("timeout-only transport failure cannot prove credential rejection", () => {
  const evidence = classifyConnectionFailure({
    error: Object.assign(new Error("connect ECONNREFUSED"), {
      code: "CONNECTION_REFUSED",
    }),
    correlation: ["synthetic-resident-a"],
  });
  assert.equal(evidence.explicit_auth, false);
  assert.equal(evidence.transport_only, true);
  assert.equal(evidence.correlated, false);
  assert.equal(
    authRejectionProved({
      clientOutcome: "connect-threw",
      evidence,
      boundedServerAuthEvent: false,
    }),
    false,
  );
});

test("correlated bounded server auth evidence can prove rejection", () => {
  const evidence = classifyConnectionFailure({
    error: Object.assign(new Error("Authorization Violation"), {
      code: "AUTHORIZATION_VIOLATION",
    }),
    serverExcerpt:
      "synthetic-resident-a-exp User Authentication Expired and revoked",
    correlation: ["synthetic-resident-a-exp"],
  });
  assert.deepEqual(
    {
      explicit_auth: evidence.explicit_auth,
      transport_only: evidence.transport_only,
      correlated: evidence.correlated,
    },
    {
      explicit_auth: true,
      transport_only: false,
      correlated: true,
    },
  );
  assert.equal(
    authRejectionProved({
      clientOutcome: "connected-then-server-closed",
      evidence,
      boundedServerAuthEvent: true,
    }),
    true,
  );
});

test("redaction and secret scan use constructed synthetic material only", () => {
  const seed = ["S", "A".repeat(55)].join("");
  const jwt = ["eyJ", "a".repeat(12), ".", "b".repeat(16), ".", "c".repeat(20)].join(
    "",
  );
  const source = `nats://user@example.invalid ${seed} ${jwt}`;
  assert.deepEqual(secretMaterialFindings(source), [
    "nkey-seed",
    "raw-jwt",
    "url-userinfo",
  ]);
  assert.deepEqual(secretMaterialFindings(redactSensitiveText(source)), []);
});

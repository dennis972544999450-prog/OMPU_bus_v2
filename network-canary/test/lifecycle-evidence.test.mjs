import assert from "node:assert/strict";
import test from "node:test";

import {
  assessLifecycleRejection,
  assessReconnectSequence,
  credentialActorSubjectSha256,
} from "../src/lifecycle-evidence.mjs";

const ATTEMPT = "attempt-1";
const ACTOR = `U${"A".repeat(55)}`;
const ACTOR_SHA = "a".repeat(64);

function syntheticCredential(subject) {
  const header = Buffer.from(JSON.stringify({ alg: "synthetic" })).toString(
    "base64url",
  );
  const payload = Buffer.from(JSON.stringify({ sub: subject })).toString(
    "base64url",
  );
  const jwt = `${header}.${payload}.synthetic`;
  return new TextEncoder().encode(
    [
      `${"-".repeat(5)}${["BEGIN NATS", "USER JWT"].join(" ")}${"-".repeat(5)}`,
      jwt,
      `${"-".repeat(6)}${["END NATS", "USER JWT"].join(" ")}${"-".repeat(6)}`,
    ].join("\n"),
  );
}

test("credential actor parser accepts canonical asymmetric delimiters", () => {
  const actor = `U${"C".repeat(55)}`;
  assert.equal(
    credentialActorSubjectSha256(syntheticCredential(actor)).length,
    64,
  );
});

test("pre-lifecycle reconnects do not contaminate denial accounting", () => {
  const sequence = assessReconnectSequence(
    [
      { type: "disconnect" },
      {
        type: "error",
        error: { message: "User Authentication Expired" },
      },
      { type: "reconnecting" },
      { type: "reconnect" },
      {
        type: "error",
        error: { message: "User Authentication Expired" },
      },
      { type: "disconnect" },
      { type: "reconnecting" },
      { type: "error", error: { message: "Authorization Violation" } },
      { type: "reconnecting" },
      { type: "error", error: { message: "Authorization Violation" } },
      { type: "reconnecting" },
      { type: "close" },
    ],
    "expiry",
  );
  assert.equal(sequence.pass, true);
  assert.equal(sequence.status_counts.reconnect, 1);
  assert.equal(sequence.post_lifecycle_status_counts.reconnect, 0);
  assert.equal(sequence.post_lifecycle_status_counts.reconnecting, 3);
  assert.equal(sequence.terminal_auth_error, true);
});

test("post-lifecycle reconnect success fails closed", () => {
  const sequence = assessReconnectSequence(
    [
      { type: "disconnect" },
      { type: "error", error: { message: "User Authentication Revoked" } },
      { type: "reconnecting" },
      { type: "reconnect" },
      { type: "reconnecting" },
      { type: "reconnecting" },
    ],
    "revocation",
  );
  assert.equal(sequence.pass, false);
  assert.equal(sequence.lifecycle_index, -1);
  assert.equal(sequence.last_successful_reconnect_index, 3);
});

test("missing reconnect loop fails closed", () => {
  const sequence = assessReconnectSequence(
    [
      { type: "disconnect" },
      { type: "error", error: { message: "User Authentication Expired" } },
      { type: "close" },
    ],
    "expiry",
  );
  assert.equal(sequence.pass, false);
  assert.equal(sequence.observed_reconnect_attempts, 0);
});

test("generic terminal auth loop is retained for external lifecycle binding", () => {
  const sequence = assessReconnectSequence(
    [
      { type: "disconnect" },
      { type: "error", error: { message: "Authorization Violation" } },
      { type: "reconnecting" },
      { type: "reconnect" },
      { type: "disconnect" },
      { type: "error", error: { message: "Authorization Violation" } },
      { type: "reconnecting" },
      { type: "error", error: { message: "Authorization Violation" } },
      { type: "reconnecting" },
      { type: "close" },
    ],
    "expiry",
  );
  assert.equal(sequence.pass, true);
  assert.equal(sequence.lifecycle_index, -1);
  assert.equal(sequence.last_successful_reconnect_index, 3);
  assert.equal(sequence.observed_reconnect_attempts, 2);
});

test("status stream may report fewer attempts than the configured budget", () => {
  const sequence = assessReconnectSequence(
    [
      { type: "disconnect" },
      { type: "error", error: { message: "User Authentication Expired" } },
      { type: "reconnecting" },
      { type: "error", error: { message: "Authorization Violation" } },
      { type: "reconnecting" },
      { type: "error", error: { message: "Authorization Violation" } },
      { type: "close" },
    ],
    "expiry",
  );
  assert.equal(sequence.pass, true);
  assert.equal(sequence.configured_max_reconnect_attempts, 3);
  assert.equal(sequence.observed_reconnect_attempts, 2);
});

test("timeout cannot prove natural expiry", () => {
  const evidence = assessLifecycleRejection({
    kind: "expiry",
    phase: "active-close",
    attemptId: ATTEMPT,
    expectedActorSha256: ACTOR_SHA,
    actorPublicKey: ACTOR,
    requireServerActor: false,
    clientResult: {
      attempt_id: ATTEMPT,
      actor_subject_sha256: ACTOR_SHA,
      outcome: "timeout",
      error: { code: "TIMEOUT", message: "timed out" },
    },
    serverExcerpt: `authentication error for ${ACTOR}`,
  });
  assert.equal(evidence.pass, false);
  assert.equal(evidence.transport_observed, true);
});

test("generic connection refusal cannot prove revocation", () => {
  const evidence = assessLifecycleRejection({
    kind: "revocation",
    phase: "fresh-connect",
    attemptId: ATTEMPT,
    expectedActorSha256: ACTOR_SHA,
    actorPublicKey: ACTOR,
    requireServerActor: true,
    clientResult: {
      attempt_id: ATTEMPT,
      actor_subject_sha256: ACTOR_SHA,
      pass: true,
      outcome: "connect-threw",
      error: {
        code: "CONNECTION_REFUSED",
        message: "connect ECONNREFUSED",
      },
    },
    serverExcerpt: `authentication error for ${ACTOR}`,
  });
  assert.equal(evidence.pass, false);
  assert.equal(evidence.transport_observed, true);
});

test("client auth error without a fresh server event fails closed", () => {
  const evidence = assessLifecycleRejection({
    kind: "revocation",
    phase: "fresh-connect",
    attemptId: ATTEMPT,
    expectedActorSha256: ACTOR_SHA,
    actorPublicKey: ACTOR,
    requireServerActor: true,
    clientResult: {
      attempt_id: ATTEMPT,
      actor_subject_sha256: ACTOR_SHA,
      pass: true,
      outcome: "connect-threw",
      error: {
        code: "AUTHORIZATION_VIOLATION",
        message: "Authorization Violation",
      },
    },
    serverExcerpt: "",
  });
  assert.equal(evidence.pass, false);
  assert.equal(evidence.client_explicit_auth, true);
  assert.equal(evidence.server_explicit_auth, false);
});

test("exact active expiry needs no duplicate server log event", () => {
  const evidence = assessLifecycleRejection({
    kind: "expiry",
    phase: "active-close",
    attemptId: ATTEMPT,
    expectedActorSha256: ACTOR_SHA,
    actorPublicKey: ACTOR,
    requireServerActor: false,
    clientResult: {
      attempt_id: ATTEMPT,
      actor_subject_sha256: ACTOR_SHA,
      pass: true,
      outcome: "connected-then-server-closed",
      error: {
        code: "AUTHORIZATION_VIOLATION",
        message: "User Authentication Expired",
      },
    },
    serverExcerpt: "",
  });
  assert.equal(evidence.pass, true);
  assert.equal(evidence.expected_lifecycle_event, true);
  assert.equal(evidence.server_explicit_auth, false);
});

test("time-bound active expiry may use actor-bound generic auth", () => {
  const evidence = assessLifecycleRejection({
    kind: "expiry",
    phase: "active-close",
    attemptId: ATTEMPT,
    expectedActorSha256: ACTOR_SHA,
    actorPublicKey: ACTOR,
    requireServerActor: true,
    controlBound: true,
    clientResult: {
      attempt_id: ATTEMPT,
      actor_subject_sha256: ACTOR_SHA,
      pass: true,
      outcome: "connected-then-server-closed",
      error: {
        code: "AUTHORIZATION_VIOLATION",
        message: "Authorization Violation",
      },
    },
    serverExcerpt: `authentication error for ${ACTOR}`,
  });
  assert.equal(evidence.pass, true);
  assert.equal(evidence.client_expected_lifecycle, false);
  assert.equal(evidence.controlled_active_denial, true);
});

test("generic active auth cannot prove expiry without time control", () => {
  const evidence = assessLifecycleRejection({
    kind: "expiry",
    phase: "active-close",
    attemptId: ATTEMPT,
    expectedActorSha256: ACTOR_SHA,
    actorPublicKey: ACTOR,
    requireServerActor: true,
    clientResult: {
      attempt_id: ATTEMPT,
      actor_subject_sha256: ACTOR_SHA,
      pass: true,
      outcome: "connected-then-server-closed",
      error: {
        code: "AUTHORIZATION_VIOLATION",
        message: "Authorization Violation",
      },
    },
    serverExcerpt: `authentication error for ${ACTOR}`,
  });
  assert.equal(evidence.pass, false);
  assert.equal(evidence.controlled_active_denial, false);
});

test("generic actor-bound auth cannot prove fresh expiry without control", () => {
  const evidence = assessLifecycleRejection({
    kind: "expiry",
    phase: "fresh-connect",
    attemptId: ATTEMPT,
    expectedActorSha256: ACTOR_SHA,
    actorPublicKey: ACTOR,
    requireServerActor: false,
    clientResult: {
      attempt_id: ATTEMPT,
      actor_subject_sha256: ACTOR_SHA,
      outcome: "connect-threw",
      error: {
        code: "AUTHORIZATION_VIOLATION",
        message: "Authorization Violation",
      },
    },
    serverExcerpt: `authentication error for ${ACTOR}`,
  });
  assert.equal(evidence.pass, false);
  assert.equal(evidence.controlled_fresh_denial, false);
});

test("controlled actor-bound server denial proves fresh expiry", () => {
  const evidence = assessLifecycleRejection({
    kind: "expiry",
    phase: "fresh-connect",
    attemptId: ATTEMPT,
    expectedActorSha256: ACTOR_SHA,
    actorPublicKey: ACTOR,
    requireServerActor: false,
    controlBound: true,
    clientResult: {
      attempt_id: ATTEMPT,
      actor_subject_sha256: ACTOR_SHA,
      pass: true,
      outcome: "connect-threw",
      error: {
        code: "AUTHORIZATION_VIOLATION",
        message: "Authorization Violation",
      },
    },
    serverExcerpt: `authentication error for ${ACTOR}`,
  });
  assert.equal(evidence.pass, true);
  assert.equal(evidence.controlled_fresh_denial, true);
});

test("generic actor-bound auth cannot prove revocation", () => {
  const evidence = assessLifecycleRejection({
    kind: "revocation",
    phase: "fresh-connect",
    attemptId: ATTEMPT,
    expectedActorSha256: ACTOR_SHA,
    actorPublicKey: ACTOR,
    requireServerActor: true,
    clientResult: {
      attempt_id: ATTEMPT,
      actor_subject_sha256: ACTOR_SHA,
      outcome: "connect-threw",
      error: {
        code: "AUTHORIZATION_VIOLATION",
        message: "Authorization Violation",
      },
    },
    serverExcerpt: `authentication error for ${ACTOR}`,
  });
  assert.equal(evidence.pass, false);
  assert.equal(evidence.expected_lifecycle_event, false);
});

test("fresh revocation evidence proves reconnect denial", () => {
  const evidence = assessLifecycleRejection({
    kind: "revocation",
    phase: "fresh-connect",
    attemptId: ATTEMPT,
    expectedActorSha256: ACTOR_SHA,
    actorPublicKey: ACTOR,
    requireServerActor: true,
    controlBound: true,
    clientResult: {
      attempt_id: ATTEMPT,
      actor_subject_sha256: ACTOR_SHA,
      pass: true,
      outcome: "connect-threw",
      error: {
        code: "AUTHORIZATION_VIOLATION",
        message: "Authorization Violation",
      },
    },
    serverExcerpt: `user authentication revoked for ${ACTOR}`,
  });
  assert.equal(evidence.pass, true);
  assert.equal(evidence.expected_lifecycle_event, true);
});

test("auth line for another actor cannot be mixed into a pass", () => {
  const otherActor = `U${"B".repeat(55)}`;
  const evidence = assessLifecycleRejection({
    kind: "revocation",
    phase: "fresh-connect",
    attemptId: ATTEMPT,
    expectedActorSha256: ACTOR_SHA,
    actorPublicKey: ACTOR,
    requireServerActor: true,
    controlBound: true,
    clientResult: {
      attempt_id: ATTEMPT,
      actor_subject_sha256: ACTOR_SHA,
      outcome: "connect-threw",
      error: {
        code: "AUTHORIZATION_VIOLATION",
        message: "Authorization Violation",
      },
    },
    serverExcerpt: `user authentication revoked for ${otherActor}`,
  });
  assert.equal(evidence.pass, false);
  assert.equal(evidence.actor_bound, true);
  assert.equal(evidence.server_actor_bound, false);
});

test("client proof for another actor cannot be mixed into a pass", () => {
  const evidence = assessLifecycleRejection({
    kind: "expiry",
    phase: "active-close",
    attemptId: ATTEMPT,
    expectedActorSha256: ACTOR_SHA,
    actorPublicKey: ACTOR,
    requireServerActor: false,
    clientResult: {
      attempt_id: ATTEMPT,
      actor_subject_sha256: "b".repeat(64),
      outcome: "connected-then-server-closed",
      error: {
        code: "AUTHORIZATION_VIOLATION",
        message: "User Authentication Expired",
      },
    },
    serverExcerpt: "",
  });
  assert.equal(evidence.pass, false);
  assert.equal(evidence.actor_bound, false);
});

test("mixed auth and transport evidence fails closed", () => {
  const evidence = assessLifecycleRejection({
    kind: "revocation",
    phase: "fresh-connect",
    attemptId: ATTEMPT,
    expectedActorSha256: ACTOR_SHA,
    actorPublicKey: ACTOR,
    requireServerActor: true,
    controlBound: true,
    clientResult: {
      attempt_id: ATTEMPT,
      actor_subject_sha256: ACTOR_SHA,
      outcome: "connect-threw",
      error: {
        code: "AUTHORIZATION_VIOLATION",
        message: "Authorization Violation after ECONNREFUSED",
      },
    },
    serverExcerpt: `user authentication revoked for ${ACTOR}`,
  });
  assert.equal(evidence.pass, false);
  assert.equal(evidence.transport_observed, true);
});

import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalSenderSubject,
  validateEvent,
} from "../src/event.mjs";
import { runSimulation } from "../src/simulation.mjs";
import { SyntheticCommons } from "../src/synthetic-transport.mjs";

function event({
  id = "evt-test-001",
  from = "synthetic-resident-a",
  to = ["synthetic-resident-b"],
  body = "synthetic payload",
} = {}) {
  return validateEvent({
    schema: "ompu.bus.event.v2",
    event_id: id,
    sent_at: "2026-07-28T00:00:00.000Z",
    from,
    to,
    body,
  });
}

function connectedCommons() {
  const commons = new SyntheticCommons();
  for (const resident of [
    "synthetic-resident-a",
    "synthetic-resident-b",
    "synthetic-resident-c",
  ]) {
    commons.connect(resident);
  }
  return commons;
}

test("COMMONS is visible to all while direct attention remains selective", () => {
  const commons = connectedCommons();
  const message = event();
  commons.publish(
    message.from,
    canonicalSenderSubject(message.from),
    message,
  );

  const readA = commons.read("synthetic-resident-a");
  const readB = commons.read("synthetic-resident-b");
  const readC = commons.read("synthetic-resident-c");
  assert.deepEqual(
    [readA.length, readB.length, readC.length],
    [1, 1, 1],
  );
  assert.deepEqual(
    [readA[0].attention, readB[0].attention, readC[0].attention],
    [false, true, false],
  );
});

test("canonical sender subject and authenticated actor must agree", () => {
  const commons = connectedCommons();
  const message = event();

  assert.throws(
    () =>
      commons.publish(
        "synthetic-resident-b",
        canonicalSenderSubject("synthetic-resident-a"),
        message,
      ),
    (error) => error.code === "PUBLISH_SUBJECT_DENIED",
  );
});

test("same message ID retry is idempotent", () => {
  const commons = connectedCommons();
  const message = event();
  const subject = canonicalSenderSubject(message.from);
  const first = commons.publish(message.from, subject, message);
  const second = commons.publish(message.from, subject, message);

  assert.deepEqual(first, { status: "stored", sequence: 1 });
  assert.deepEqual(second, { status: "duplicate", sequence: 1 });
  assert.equal(commons.messageCount, 1);
});

test("same message ID with changed content is rejected", () => {
  const commons = connectedCommons();
  const first = event();
  const changed = event({ body: "different synthetic payload" });
  const subject = canonicalSenderSubject(first.from);
  commons.publish(first.from, subject, first);

  assert.throws(
    () => commons.publish(changed.from, subject, changed),
    (error) => error.code === "MESSAGE_ID_CONFLICT",
  );
});

test("extra event fields and credential-shaped payloads fail closed", () => {
  assert.throws(
    () =>
      validateEvent({
        schema: "ompu.bus.event.v2",
        event_id: "evt-test-extra",
        sent_at: "2026-07-28T00:00:00.000Z",
        from: "synthetic-resident-a",
        to: [],
        body: "synthetic payload",
        credentialFile: "/private/example.creds",
      }),
    (error) => error.code === "EVENT_FIELD_FORBIDDEN",
  );

  const commons = connectedCommons();
  const shapedBody = ["gh", "p_", "A".repeat(36)].join("");
  const shaped = event({ id: "evt-test-shaped", body: shapedBody });
  assert.throws(
    () =>
      commons.publish(
        shaped.from,
        canonicalSenderSubject(shaped.from),
        shaped,
      ),
    (error) => error.code === "CREDENTIAL_SHAPE_FORBIDDEN",
  );
});

test("resident cursors advance independently with compare-and-set", () => {
  const commons = connectedCommons();
  const first = event();
  const second = event({
    id: "evt-test-002",
    from: "synthetic-resident-c",
    to: [],
  });
  commons.publish(first.from, canonicalSenderSubject(first.from), first);
  commons.acknowledge("synthetic-resident-b", { expect: 0, through: 1 });
  commons.publish(second.from, canonicalSenderSubject(second.from), second);

  assert.equal(commons.read("synthetic-resident-b").length, 1);
  assert.equal(commons.read("synthetic-resident-a").length, 2);
  assert.throws(
    () =>
      commons.acknowledge("synthetic-resident-b", {
        expect: 0,
        through: 2,
      }),
    (error) => error.code === "CURSOR_CONFLICT",
  );
});

test("revoked resident cannot reconnect, read, or publish", () => {
  const commons = connectedCommons();
  const message = event();
  commons.revoke("synthetic-resident-a");

  for (const operation of [
    () => commons.connect("synthetic-resident-a"),
    () => commons.read("synthetic-resident-a"),
    () =>
      commons.publish(
        "synthetic-resident-a",
        canonicalSenderSubject("synthetic-resident-a"),
        message,
      ),
  ]) {
    assert.throws(operation, (error) => error.code === "RESIDENT_REVOKED");
  }
});

test("deterministic end-to-end simulation keeps external resident on HOLD", () => {
  assert.deepEqual(runSimulation(), {
    schema: "ompu.bus2.synthetic-simulation.v0.1",
    status: "PASS",
    externalResident: "HOLD",
    storedSequences: [1, 2],
    allResidentsSawFirst: true,
    directAttentionOnlyForB: true,
    duplicateWasIdempotent: true,
    offlineResumeFromIndependentCursor: true,
    revokedReconnectDenied: true,
  });
});

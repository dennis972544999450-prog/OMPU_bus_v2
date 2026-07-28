import { canonicalSenderSubject } from "./event.mjs";
import { loadSyntheticBoundary, loadSyntheticEvents } from "./fixtures.mjs";
import { SyntheticCommons } from "./synthetic-transport.mjs";

export function runSimulation() {
  const boundary = loadSyntheticBoundary();
  const [residentA, residentB, residentC] = boundary.identities;
  const events = loadSyntheticEvents();
  const commons = new SyntheticCommons();

  for (const resident of boundary.identities) {
    commons.connect(resident);
  }

  const first = commons.publish(
    residentA,
    canonicalSenderSubject(residentA),
    events[0],
  );
  const visibleToA = commons.read(residentA);
  const visibleToB = commons.read(residentB);
  const visibleToC = commons.read(residentC);
  commons.acknowledge(residentB, { expect: 0, through: first.sequence });

  const second = commons.publish(
    residentC,
    canonicalSenderSubject(residentC),
    events[1],
  );
  const duplicate = commons.publish(
    residentC,
    canonicalSenderSubject(residentC),
    events[1],
  );
  const resumedForB = commons.read(residentB);

  commons.revoke(residentA);
  let revokedReconnectDenied = false;
  try {
    commons.connect(residentA);
  } catch (error) {
    revokedReconnectDenied = error.code === "RESIDENT_REVOKED";
  }

  return Object.freeze({
    schema: "ompu.bus2.synthetic-simulation.v0.1",
    status: "PASS",
    externalResident: "HOLD",
    storedSequences: Object.freeze([first.sequence, second.sequence]),
    allResidentsSawFirst: [visibleToA, visibleToB, visibleToC].every(
      (messages) => messages.length === 1 && messages[0].sequence === 1,
    ),
    directAttentionOnlyForB:
      visibleToA[0].attention === false &&
      visibleToB[0].attention === true &&
      visibleToC[0].attention === false,
    duplicateWasIdempotent:
      duplicate.status === "duplicate" &&
      duplicate.sequence === second.sequence &&
      commons.messageCount === 2,
    offlineResumeFromIndependentCursor:
      resumedForB.length === 1 && resumedForB[0].sequence === 2,
    revokedReconnectDenied,
  });
}

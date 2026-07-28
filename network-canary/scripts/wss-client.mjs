import {
  readFileSync,
  writeFileSync,
} from "node:fs";

import {
  credsAuthenticator,
  wsconnect,
} from "@nats-io/nats-core";
import {
  AckPolicy,
  DeliverPolicy,
  DiscardPolicy,
  ReplayPolicy,
  RetentionPolicy,
  StorageType,
  jetstream,
  jetstreamManager,
} from "@nats-io/jetstream";

import {
  DURABLE_A,
  DURABLE_B,
  STREAM,
  SUBJECT_A,
  SUBJECT_B,
} from "../src/contracts.mjs";
import { assertSecretFree, safeError } from "../src/safety.mjs";

const config = JSON.parse(process.env.OMPU_NETWORK_CANARY_CLIENT || "{}");
const encoder = new TextEncoder();
let stage = "startup";

function requiredString(name) {
  const value = config[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`missing client setting: ${name}`);
  }
  return value;
}

async function connectWithCredentials(kind, label) {
  const credentialsPath = requiredString(`${kind}Credentials`);
  const bytes = readFileSync(credentialsPath);
  try {
    return await wsconnect({
      servers: [requiredString("wssUrl")],
      authenticator: credsAuthenticator(bytes),
      name: label,
      inboxPrefix: `_INBOX.OMPU.NET.${kind.toUpperCase()}`,
      reconnect: false,
      maxReconnectAttempts: 0,
      noRandomize: true,
      timeout: 4_000,
    });
  } finally {
    bytes.fill(0);
  }
}

async function close(connection) {
  if (connection && !connection.isClosed()) {
    await connection.close();
  }
}

function consumerConfig(name) {
  return {
    durable_name: name,
    name,
    filter_subject: "commons.>",
    ack_policy: AckPolicy.Explicit,
    deliver_policy: DeliverPolicy.All,
    replay_policy: ReplayPolicy.Instant,
    ack_wait: 30_000_000_000,
    max_ack_pending: 16,
  };
}

async function nextSequence(consumer, label) {
  const message = await consumer.next({ expires: 4_000 });
  if (!message) {
    throw new Error(`durable consumer timed out: ${label}`);
  }
  const sequence = message.info.streamSequence;
  const acknowledged = await message.ackAck({ timeout: 2_000 });
  if (!acknowledged) {
    throw new Error(`durable consumer did not confirm ack: ${label}`);
  }
  return sequence;
}

async function publish(client, subject, label) {
  const acknowledgement = await client.publish(
    subject,
    encoder.encode(JSON.stringify({ fixture: label })),
    { msgID: `ompu-network-canary-${label}` },
  );
  return acknowledgement.seq;
}

async function main() {
  let bootstrap;
  let residentA;
  let residentB;
  let resumedA;
  try {
    stage = "connect-bootstrap";
    bootstrap = await connectWithCredentials("bootstrap", "network-bootstrap");
    stage = "create-stream";
    const manager = await jetstreamManager(bootstrap, { timeout: 3_000 });
    await manager.streams.add({
      name: STREAM,
      description: "Synthetic OMPU Bus 2.0 WSS canary",
      subjects: [SUBJECT_A, SUBJECT_B],
      retention: RetentionPolicy.Limits,
      storage: StorageType.File,
      discard: DiscardPolicy.New,
      num_replicas: 1,
      max_msgs: 64,
      duplicate_window: 120_000_000_000,
      deny_delete: true,
      deny_purge: true,
    });
    stage = "create-consumer-a";
    await manager.consumers.add(STREAM, consumerConfig(DURABLE_A));
    stage = "create-consumer-b";
    await manager.consumers.add(STREAM, consumerConfig(DURABLE_B));
    await close(bootstrap);
    bootstrap = null;

    stage = "connect-residents";
    residentA = await connectWithCredentials("a", "synthetic-resident-a");
    residentB = await connectWithCredentials("b", "synthetic-resident-b");
    const jsA = jetstream(residentA, { timeout: 3_000 });
    const jsB = jetstream(residentB, { timeout: 3_000 });
    const consumerA = await jsA.consumers.get(STREAM, DURABLE_A);
    const consumerB = await jsB.consumers.get(STREAM, DURABLE_B);

    stage = "initial-publish";
    const published = [
      await publish(jsA, SUBJECT_A, "resident-a-1"),
      await publish(jsB, SUBJECT_B, "resident-b-1"),
    ];
    stage = "initial-consume";
    const readA = [
      await nextSequence(consumerA, "a-sequence-1"),
      await nextSequence(consumerA, "a-sequence-2"),
    ];
    const readB = [
      await nextSequence(consumerB, "b-sequence-1"),
      await nextSequence(consumerB, "b-sequence-2"),
    ];

    stage = "sender-acl";
    let senderAclDenied = false;
    let senderAclError = null;
    try {
      await publish(jsA, SUBJECT_B, "resident-a-forbidden");
    } catch (error) {
      senderAclDenied = true;
      senderAclError = safeError(error);
    }
    const senderAclExplicit =
      senderAclDenied &&
      /permission/i.test(senderAclError?.message || "");

    stage = "offline-publish";
    await close(residentA);
    residentA = null;
    const offlineSequence = await publish(
      jsB,
      SUBJECT_B,
      "resident-b-while-a-offline",
    );
    const bOfflineRead = await nextSequence(consumerB, "b-offline-sequence");

    stage = "resume-resident-a";
    resumedA = await connectWithCredentials("a", "synthetic-resident-a-resume");
    const resumedJsA = jetstream(resumedA, { timeout: 3_000 });
    const resumedConsumerA = await resumedJsA.consumers.get(STREAM, DURABLE_A);
    const aResumedRead = await nextSequence(
      resumedConsumerA,
      "a-resumed-sequence",
    );
    const infoManager = await jetstreamManager(resumedA, { timeout: 3_000 });
    const streamInfo = await infoManager.streams.info(STREAM);

    const proof = {
      pass:
        JSON.stringify(published) === JSON.stringify([1, 2]) &&
        JSON.stringify(readA) === JSON.stringify([1, 2]) &&
        JSON.stringify(readB) === JSON.stringify([1, 2]) &&
        senderAclExplicit &&
        offlineSequence === 3 &&
        bOfflineRead === 3 &&
        aResumedRead === 3 &&
        streamInfo.state.messages === 3 &&
        streamInfo.state.last_seq === 3,
      transport: {
        scheme: "wss",
        tls_verified: true,
        loopback_only: true,
      },
      commons: {
        stream: STREAM,
        subjects: [SUBJECT_A, SUBJECT_B],
        published_sequences: published,
        resident_a_sequences: readA,
        resident_b_sequences: readB,
      },
      sender_acl: {
        denied_cross_subject_publish: senderAclDenied,
        explicit_permission_error: senderAclExplicit,
        error: senderAclError,
      },
      offline_resume: {
        published_while_a_offline: offlineSequence,
        resident_b_sequence: bOfflineRead,
        resident_a_resumed_sequence: aResumedRead,
      },
      stream_accounting: {
        messages: streamInfo.state.messages,
        last_sequence: streamInfo.state.last_seq,
      },
    };
    assertSecretFree(proof, "client proof");
    writeFileSync(
      requiredString("resultPath"),
      `${JSON.stringify(proof, null, 2)}\n`,
      { mode: 0o600 },
    );
    if (!proof.pass) {
      throw new Error("network semantics did not satisfy the canary contract");
    }
  } finally {
    await close(bootstrap);
    await close(residentA);
    await close(residentB);
    await close(resumedA);
  }
}

main().catch((error) => {
  const wrapped = new Error(`${stage}: ${error?.message || String(error)}`);
  wrapped.code = typeof error?.code === "string" ? error.code : null;
  process.stderr.write(`${JSON.stringify(safeError(wrapped))}\n`);
  process.exitCode = 1;
});

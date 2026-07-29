import { readFileSync } from "node:fs";

import {
  credsAuthenticator,
  wsconnect,
} from "@nats-io/nats-core";

import {
  safeError,
  writeBoundedJson,
} from "../src/safety.mjs";
import {
  assessReconnectSequence,
  credentialActorSubjectSha256,
} from "../src/lifecycle-evidence.mjs";

const config = JSON.parse(
  process.env.OMPU_NETWORK_LIFECYCLE_CLIENT || "{}",
);

function requiredString(name) {
  const value = config[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`missing lifecycle client setting: ${name}`);
  }
  return value;
}

async function waitForConnectionClose(connection, timeoutMs) {
  return await new Promise((resolve) => {
    const timer = setTimeout(
      () => resolve({ kind: "timeout", error: null }),
      timeoutMs,
    );
    connection.closed().then((error) => {
      clearTimeout(timer);
      resolve({ kind: "closed", error });
    });
  });
}

function connectionOptions(authenticator, reconnect) {
  return {
    servers: [requiredString("wssUrl")],
    authenticator,
    name: requiredString("label"),
    inboxPrefix: "_INBOX.OMPU.NET.LIFECYCLE",
    reconnect,
    maxReconnectAttempts: reconnect ? 3 : 0,
    reconnectTimeWait: 200,
    reconnectJitter: 0,
    reconnectJitterTLS: 0,
    ignoreAuthErrorAbort: reconnect,
    noRandomize: true,
    timeout: 4_000,
  };
}

async function connectOnce() {
  const bytes = readFileSync(requiredString("credentialsPath"));
  const actor = credentialActorSubjectSha256(bytes);
  try {
    const connection = await wsconnect(
      connectionOptions(credsAuthenticator(bytes), false),
    );
    return { connection, actor };
  } finally {
    bytes.fill(0);
  }
}

async function awaitServerClose() {
  const bytes = readFileSync(requiredString("credentialsPath"));
  const actor = credentialActorSubjectSha256(bytes);
  let connection;
  try {
    connection = await wsconnect(
      connectionOptions(credsAuthenticator(bytes), true),
    );
    const statuses = [];
    const statusTask = (async () => {
      for await (const status of connection.status()) {
        if (
          status.type === "disconnect" ||
          status.type === "reconnecting" ||
          status.type === "reconnect" ||
          status.type === "close"
        ) {
          statuses.push({ type: status.type, at: Date.now() });
        } else if (status.type === "error") {
          statuses.push({
            type: status.type,
            at: Date.now(),
            error: safeError(status.error),
          });
        }
      }
    })();

    await connection.flush();
    writeBoundedJson(requiredString("readyPath"), {
      ready: true,
      attempt_id: requiredString("attemptId"),
      ready_at: Math.floor(Date.now() / 1000),
    });

    const timeoutMs = Number(config.timeoutMs ?? 80_000);
    const result = await waitForConnectionClose(connection, timeoutMs);

    if (result.kind === "timeout") {
      await connection.close();
      await statusTask;
      return {
        attempt_id: requiredString("attemptId"),
        actor_subject_sha256: actor,
        pass: false,
        outcome: "timeout",
        error: null,
        statuses,
      };
    }
    await statusTask;
    const sequence = assessReconnectSequence(
      statuses,
      requiredString("kind"),
      3,
    );
    return {
      attempt_id: requiredString("attemptId"),
      actor_subject_sha256: actor,
      pass: sequence.pass,
      outcome: "connected-then-server-closed",
      error:
        sequence.lifecycle_error ||
        (result.error ? safeError(result.error) : null),
      status_counts: sequence.status_counts,
      post_lifecycle_status_counts:
        sequence.post_lifecycle_status_counts,
    };
  } finally {
    bytes.fill(0);
  }
}

async function expectRejected() {
  let connection;
  let actor = null;
  try {
    ({ connection, actor } = await connectOnce());
    await connection.flush();
    await connection.close();
    return {
      attempt_id: requiredString("attemptId"),
      actor_subject_sha256: actor,
      pass: false,
      outcome: "unexpected-connect",
      error: null,
    };
  } catch (error) {
    if (!actor) {
      const bytes = readFileSync(requiredString("credentialsPath"));
      try {
        actor = credentialActorSubjectSha256(bytes);
      } finally {
        bytes.fill(0);
      }
    }
    return {
      attempt_id: requiredString("attemptId"),
      actor_subject_sha256: actor,
      pass: true,
      outcome: "connect-threw",
      error: safeError(error),
    };
  }
}

async function expectConnected() {
  let connection;
  let actor = null;
  try {
    ({ connection, actor } = await connectOnce());
    await connection.flush();
    await connection.close();
    return {
      attempt_id: requiredString("attemptId"),
      actor_subject_sha256: actor,
      pass: true,
      outcome: "connected-and-flushed",
      error: null,
    };
  } catch (error) {
    return {
      attempt_id: requiredString("attemptId"),
      actor_subject_sha256: actor,
      pass: false,
      outcome: "healthy-control-failed",
      error: safeError(error),
    };
  }
}

async function main() {
  const mode = requiredString("mode");
  let result;
  if (mode === "await-close") {
    result = await awaitServerClose();
  } else if (mode === "expect-rejected") {
    result = await expectRejected();
  } else if (mode === "expect-connected") {
    result = await expectConnected();
  } else {
    throw new Error(`unknown lifecycle client mode: ${mode}`);
  }
  writeBoundedJson(requiredString("resultPath"), result);
}

main().catch((error) => {
  const resultPath = config.resultPath;
  if (typeof resultPath === "string" && resultPath.length > 0) {
    writeBoundedJson(resultPath, {
      attempt_id:
        typeof config.attemptId === "string" ? config.attemptId : "missing",
      pass: false,
      outcome: "client-threw",
      error: safeError(error),
    });
  }
  process.exitCode = 1;
});

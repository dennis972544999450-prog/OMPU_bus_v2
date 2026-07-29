import { createHash } from "node:crypto";

const AUTH_PATTERN =
  /auth(?:entication|orization)?|expired|expiration|revok|permissions violation/i;
const TRANSPORT_PATTERN =
  /ECONNREFUSED|connection refused|timeout|timed out|socket closed/i;
const JWT_BEGIN = ["BEGIN NATS", "USER JWT"].join(" ");
const JWT_END = ["END NATS", "USER JWT"].join(" ");

function sha256(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function errorText(error) {
  if (!error || typeof error !== "object") {
    return String(error ?? "");
  }
  return [
    typeof error.code === "string" ? error.code : "",
    typeof error.message === "string" ? error.message : "",
  ]
    .filter(Boolean)
    .join(" ");
}

function expectedPattern(kind) {
  if (kind === "expiry") {
    return /expired|expiration/i;
  }
  if (kind === "revocation") {
    return /revok/i;
  }
  throw new Error(`unknown lifecycle evidence kind: ${kind}`);
}

function statusCounts(statuses) {
  return Object.fromEntries(
    ["disconnect", "reconnecting", "reconnect", "error", "close"].map(
      (type) => [
        type,
        statuses.filter((status) => status.type === type).length,
      ],
    ),
  );
}

export function assessReconnectSequence(statuses, kind, maxAttempts = 3) {
  if (!Array.isArray(statuses)) {
    throw new TypeError("statuses must be an array");
  }
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) {
    throw new TypeError("maxAttempts must be a positive integer");
  }
  const lastReconnectIndex = statuses.findLastIndex(
    (status) => status?.type === "reconnect",
  );
  const lifecycleIndex = statuses.findIndex(
    (status, index) =>
      index > lastReconnectIndex &&
      status?.type === "error" &&
      expectedPattern(kind).test(errorText(status.error)),
  );
  const postLifecycle =
    lifecycleIndex >= 0 ? statuses.slice(lifecycleIndex) : [];
  const total = statusCounts(statuses);
  const afterLifecycle = statusCounts(postLifecycle);
  const observedReconnectAttempts = afterLifecycle.reconnecting;
  return Object.freeze({
    pass:
      lifecycleIndex >= 0 &&
      total.disconnect >= 1 &&
      observedReconnectAttempts >= 1 &&
      observedReconnectAttempts <= maxAttempts &&
      afterLifecycle.reconnect === 0 &&
      afterLifecycle.error >= observedReconnectAttempts &&
      afterLifecycle.close === 1,
    lifecycle_index: lifecycleIndex,
    last_successful_reconnect_index: lastReconnectIndex,
    configured_max_reconnect_attempts: maxAttempts,
    observed_reconnect_attempts: observedReconnectAttempts,
    lifecycle_error:
      lifecycleIndex >= 0 ? statuses[lifecycleIndex].error : null,
    status_counts: total,
    post_lifecycle_status_counts: afterLifecycle,
  });
}

export function credentialActorSubjectSha256(bytes) {
  const text = new TextDecoder().decode(bytes);
  const pattern = new RegExp(
    `[-]{3,}${JWT_BEGIN}[-]{3,}\\s*([^\\s]+)\\s*[-]{3,}${JWT_END}[-]{3,}`,
  );
  const match = pattern.exec(text);
  if (!match) {
    throw new Error("unable to locate user JWT in credentials");
  }
  const pieces = match[1].split(".");
  if (pieces.length !== 3) {
    throw new Error("credential JWT has invalid shape");
  }
  const payload = JSON.parse(
    Buffer.from(pieces[1], "base64url").toString("utf8"),
  );
  if (
    typeof payload.sub !== "string" ||
    !/^U[A-Z2-7]{55}$/.test(payload.sub)
  ) {
    throw new Error("credential JWT has no public user subject");
  }
  return sha256(payload.sub);
}

export function assessLifecycleRejection({
  kind,
  phase,
  attemptId,
  expectedActorSha256,
  actorPublicKey,
  requireServerActor,
  controlBound = false,
  clientResult,
  serverExcerpt,
}) {
  const client = errorText(clientResult?.error);
  const server = String(serverExcerpt ?? "");
  const combined = `${client}\n${server}`;
  const expectedOutcome =
    phase === "active-close"
      ? "connected-then-server-closed"
      : phase === "fresh-connect"
        ? "connect-threw"
        : null;
  if (!expectedOutcome) {
    throw new Error(`unknown lifecycle evidence phase: ${phase}`);
  }
  const attemptBound =
    typeof attemptId === "string" &&
    attemptId.length > 0 &&
    clientResult?.attempt_id === attemptId;
  const actorBound =
    typeof expectedActorSha256 === "string" &&
    expectedActorSha256.length === 64 &&
    clientResult?.actor_subject_sha256 === expectedActorSha256;
  const serverActorBound =
    typeof actorPublicKey === "string" &&
    actorPublicKey.length > 0 &&
    server.includes(actorPublicKey);
  const clientExplicitAuth = AUTH_PATTERN.test(client);
  const serverExplicitAuth = AUTH_PATTERN.test(server);
  const clientExpectedLifecycle = expectedPattern(kind).test(client);
  const serverExpectedLifecycle = expectedPattern(kind).test(server);
  const controlledFreshDenial =
    phase === "fresh-connect" &&
    controlBound &&
    serverExplicitAuth &&
    serverActorBound;
  const expectedLifecycleEvent =
    clientExpectedLifecycle || controlledFreshDenial;
  const transportObserved = TRANSPORT_PATTERN.test(combined);

  return Object.freeze({
    pass:
      clientResult?.outcome === expectedOutcome &&
      attemptBound &&
      actorBound &&
      clientExplicitAuth &&
      (!requireServerActor || (serverExplicitAuth && serverActorBound)) &&
      expectedLifecycleEvent &&
      !transportObserved,
    kind,
    phase,
    client_outcome: clientResult?.outcome ?? "missing",
    attempt_bound: attemptBound,
    actor_bound: actorBound,
    control_bound: Boolean(controlBound),
    server_actor_required: Boolean(requireServerActor),
    server_actor_bound: serverActorBound,
    client_explicit_auth: clientExplicitAuth,
    server_explicit_auth: serverExplicitAuth,
    client_expected_lifecycle: clientExpectedLifecycle,
    server_expected_lifecycle: serverExpectedLifecycle,
    controlled_fresh_denial: controlledFreshDenial,
    expected_lifecycle_event: expectedLifecycleEvent,
    transport_observed: transportObserved,
    evidence_sha256: sha256(combined),
  });
}

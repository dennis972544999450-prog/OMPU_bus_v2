import { createHash } from "node:crypto";

const JWT_SEGMENT = /^[A-Za-z0-9_-]+$/;

function evidenceError(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function sha256(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

export function decodePublicJwtPayload(jwt) {
  const pieces = String(jwt).trim().split(".");
  if (
    pieces.length !== 3 ||
    pieces.some((piece) => piece.length === 0 || !JWT_SEGMENT.test(piece))
  ) {
    evidenceError("JWT_SHAPE_INVALID", "JWT must contain three base64url segments");
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(pieces[1], "base64url").toString("utf8"));
  } catch {
    evidenceError("JWT_PAYLOAD_INVALID", "JWT payload is not valid JSON");
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    evidenceError("JWT_PAYLOAD_INVALID", "JWT payload must be an object");
  }
  return payload;
}

export function safePublicClaimIndex(label, jwt) {
  const payload = decodePublicJwtPayload(jwt);
  return Object.freeze({
    label,
    jwt_sha256: sha256(jwt),
    issuer: payload.iss ?? null,
    subject: payload.sub ?? null,
    jti: payload.jti ?? null,
    issued_at: payload.iat ?? null,
    expires_at: payload.exp ?? null,
    name: payload.name ?? null,
    publish_allow: Object.freeze([...(payload?.nats?.pub?.allow ?? [])]),
    subscribe_allow: Object.freeze([...(payload?.nats?.sub?.allow ?? [])]),
  });
}

export function redactSensitiveText(value) {
  return String(value)
    .replace(
      /-----BEGIN NATS USER JWT-----[\s\S]*?-----END USER NKEY SEED-----/g,
      "<redacted-nats-credentials>",
    )
    .replace(/\bS[A-Z2-7]{55}\b/g, "<redacted-nkey-seed>")
    .replace(
      /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
      "<redacted-jwt>",
    )
    .replace(/(nats:\/\/)[^/@\s]+@/gi, "$1");
}

export function secretMaterialFindings(value) {
  const source = String(value);
  const findings = [];
  if (/\bS[A-Z2-7]{55}\b/.test(source)) {
    findings.push("nkey-seed");
  }
  if (/BEGIN NATS USER JWT|BEGIN USER NKEY SEED/.test(source)) {
    findings.push("credentials-block");
  }
  if (/\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/.test(source)) {
    findings.push("raw-jwt");
  }
  if (/nats:\/\/[^/@\s]+@/i.test(source)) {
    findings.push("url-userinfo");
  }
  return Object.freeze(findings);
}

export function classifyConnectionFailure({
  error,
  statuses = [],
  serverExcerpt = "",
  correlation = [],
}) {
  const errorText =
    error instanceof Error
      ? `${typeof error.code === "string" ? error.code : ""} ${error.message}`
      : String(error ?? "");
  const rawTranscript = [
    errorText,
    JSON.stringify(statuses),
    String(serverExcerpt),
  ].join(" ");
  const redactedTranscript = redactSensitiveText(rawTranscript);
  const explicitAuth =
    /auth(?:entication|orization)?|expired|revok|permissions violation/i.test(
      redactedTranscript,
    );
  const transportOnly =
    /ECONNREFUSED|connection refused|timeout|timed out|socket closed/i.test(
      redactedTranscript,
    );
  const correlated = correlation.some(
    (handle) =>
      typeof handle === "string" &&
      handle.length > 0 &&
      rawTranscript.includes(handle),
  );

  return Object.freeze({
    explicit_auth: explicitAuth,
    transport_only: transportOnly && !explicitAuth,
    correlated,
    transcript_sha256: sha256(redactedTranscript),
  });
}

export function authRejectionProved({
  clientOutcome,
  evidence,
  boundedServerAuthEvent,
}) {
  const rejected =
    clientOutcome === "connect-threw" ||
    clientOutcome === "connected-then-server-closed";
  return Boolean(
    rejected &&
      evidence?.explicit_auth &&
      evidence?.correlated &&
      boundedServerAuthEvent === true &&
      evidence?.transport_only === false,
  );
}

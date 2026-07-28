import { createHash } from "node:crypto";

import { isSyntheticIdentity } from "./security-boundary.mjs";

const EVENT_ID = /^[a-z0-9][a-z0-9._:-]{2,80}$/;
const EVENT_FIELDS = Object.freeze([
  "body",
  "event_id",
  "from",
  "schema",
  "sent_at",
  "to",
]);

function eventError(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function digestEvent(event) {
  return createHash("sha256").update(canonicalJson(event)).digest("hex");
}

export function canonicalSenderSubject(resident) {
  if (!isSyntheticIdentity(resident)) {
    eventError("SENDER_INVALID", "sender must be a synthetic resident");
  }
  return `commons.${resident}`;
}

export function validateEvent(event) {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    eventError("EVENT_INVALID", "event must be an object");
  }
  const fields = Object.keys(event).sort();
  if (
    fields.length !== EVENT_FIELDS.length ||
    !fields.every((field, index) => field === EVENT_FIELDS[index])
  ) {
    eventError("EVENT_FIELD_FORBIDDEN", "event fields must match the schema");
  }
  if (event.schema !== "ompu.bus.event.v2") {
    eventError("SCHEMA_INVALID", "event schema must be ompu.bus.event.v2");
  }
  if (typeof event.event_id !== "string" || !EVENT_ID.test(event.event_id)) {
    eventError("EVENT_ID_INVALID", "event_id has an invalid shape");
  }
  if (
    typeof event.sent_at !== "string" ||
    Number.isNaN(Date.parse(event.sent_at)) ||
    new Date(event.sent_at).toISOString() !== event.sent_at
  ) {
    eventError("SENT_AT_INVALID", "sent_at must be an ISO-8601 UTC timestamp");
  }
  if (!isSyntheticIdentity(event.from)) {
    eventError("SENDER_INVALID", "from must be a synthetic resident");
  }
  if (
    !Array.isArray(event.to) ||
    !event.to.every(isSyntheticIdentity) ||
    new Set(event.to).size !== event.to.length
  ) {
    eventError("RECIPIENT_INVALID", "to must contain unique synthetic residents");
  }
  if (
    typeof event.body !== "string" ||
    event.body.length === 0 ||
    event.body.length > 4096
  ) {
    eventError("BODY_INVALID", "body must contain 1 to 4096 characters");
  }

  return Object.freeze({
    schema: event.schema,
    event_id: event.event_id,
    sent_at: event.sent_at,
    from: event.from,
    to: Object.freeze([...event.to]),
    body: event.body,
  });
}

export function isAttentionFor(event, resident) {
  return event.to.length === 0 || event.to.includes(resident);
}

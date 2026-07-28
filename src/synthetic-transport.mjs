import {
  canonicalSenderSubject,
  digestEvent,
  isAttentionFor,
  validateEvent,
} from "./event.mjs";
import {
  containsCredentialShape,
  isSyntheticIdentity,
} from "./security-boundary.mjs";

function transportError(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

export class SyntheticCommons {
  #residents = new Set();
  #revoked = new Set();
  #messages = [];
  #messageIds = new Map();
  #cursors = new Map();

  connect(resident) {
    if (!isSyntheticIdentity(resident)) {
      transportError("RESIDENT_INVALID", "resident label is not synthetic");
    }
    if (this.#revoked.has(resident)) {
      transportError("RESIDENT_REVOKED", "revoked resident cannot reconnect");
    }
    this.#residents.add(resident);
    if (!this.#cursors.has(resident)) {
      this.#cursors.set(resident, 0);
    }
    return Object.freeze({ resident, cursor: this.#cursors.get(resident) });
  }

  revoke(resident) {
    this.#assertKnown(resident);
    this.#revoked.add(resident);
    return Object.freeze({ resident, revoked: true });
  }

  publish(actor, subject, event, { messageId = event?.event_id } = {}) {
    this.#assertActive(actor);
    const normalized = validateEvent(event);
    const expectedSubject = canonicalSenderSubject(actor);

    if (subject !== expectedSubject || normalized.from !== actor) {
      transportError(
        "PUBLISH_SUBJECT_DENIED",
        "resident may publish only as its canonical sender",
      );
    }
    if (messageId !== normalized.event_id) {
      transportError("MESSAGE_ID_MISMATCH", "message ID must equal event_id");
    }
    if (containsCredentialShape(normalized)) {
      transportError(
        "CREDENTIAL_SHAPE_FORBIDDEN",
        "credential-shaped event content is forbidden",
      );
    }

    const digest = digestEvent(normalized);
    const previous = this.#messageIds.get(messageId);
    if (previous) {
      if (previous.digest !== digest || previous.subject !== subject) {
        transportError(
          "MESSAGE_ID_CONFLICT",
          "message ID was already used for different content",
        );
      }
      return Object.freeze({
        status: "duplicate",
        sequence: previous.sequence,
      });
    }

    const sequence = this.#messages.length + 1;
    const stored = Object.freeze({
      sequence,
      subject,
      event: normalized,
      digest,
    });
    this.#messages.push(stored);
    this.#messageIds.set(messageId, stored);

    return Object.freeze({ status: "stored", sequence });
  }

  read(resident, { after } = {}) {
    this.#assertActive(resident);
    const cursor = after ?? this.#cursors.get(resident);

    if (!Number.isSafeInteger(cursor) || cursor < 0) {
      transportError("CURSOR_INVALID", "cursor must be a non-negative integer");
    }

    return this.#messages
      .filter((message) => message.sequence > cursor)
      .map((message) =>
        Object.freeze({
          sequence: message.sequence,
          subject: message.subject,
          event: message.event,
          attention: isAttentionFor(message.event, resident),
        }),
      );
  }

  acknowledge(resident, { expect, through }) {
    this.#assertActive(resident);
    const current = this.#cursors.get(resident);

    if (expect !== current) {
      transportError("CURSOR_CONFLICT", "cursor compare-and-set failed");
    }
    if (
      !Number.isSafeInteger(through) ||
      through < current ||
      through > this.#messages.length
    ) {
      transportError("CURSOR_INVALID", "acknowledgement cursor is out of range");
    }

    this.#cursors.set(resident, through);
    return Object.freeze({ resident, previous: current, cursor: through });
  }

  cursor(resident) {
    this.#assertKnown(resident);
    return this.#cursors.get(resident);
  }

  get messageCount() {
    return this.#messages.length;
  }

  #assertKnown(resident) {
    if (!this.#residents.has(resident)) {
      transportError("RESIDENT_UNKNOWN", "resident must connect first");
    }
  }

  #assertActive(resident) {
    this.#assertKnown(resident);
    if (this.#revoked.has(resident)) {
      transportError("RESIDENT_REVOKED", "resident is revoked");
    }
  }
}

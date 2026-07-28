const SYNTHETIC_ID = /^synthetic-resident-[a-z0-9][a-z0-9-]{0,48}$/;
const BOUNDARY_FIELDS = new Set([
  "schema",
  "mode",
  "endpoint",
  "liveBusBridge",
  "publicEndpoint",
  "realCredentials",
  "deploy",
  "networkIntegration",
  "identities",
]);

const CREDENTIAL_PATTERNS = Object.freeze([
  /\bS[A-Z2-7]{55}\b/,
  /-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----/,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
  /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*\b/i,
]);

function boundaryError(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

export function isSyntheticIdentity(value) {
  return typeof value === "string" && SYNTHETIC_ID.test(value);
}

export function containsCredentialShape(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return CREDENTIAL_PATTERNS.some((pattern) => pattern.test(text));
}

export function assertSyntheticBoundary(config) {
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    boundaryError("BOUNDARY_CONFIG_INVALID", "boundary config must be an object");
  }
  if (config.schema !== "ompu.bus2.synthetic-boundary.v0.1") {
    boundaryError("BOUNDARY_SCHEMA_INVALID", "boundary schema is not supported");
  }
  const unknownFields = Object.keys(config).filter(
    (field) => !BOUNDARY_FIELDS.has(field),
  );
  if (unknownFields.length > 0) {
    boundaryError(
      "BOUNDARY_FIELD_FORBIDDEN",
      `unknown boundary fields: ${unknownFields.sort().join(", ")}`,
    );
  }
  if (config.mode !== "synthetic-only") {
    boundaryError("LIVE_MODE_FORBIDDEN", "only synthetic-only mode is permitted");
  }
  if (config.endpoint !== null) {
    boundaryError("ENDPOINT_FORBIDDEN", "network endpoints are forbidden");
  }

  for (const field of [
    "liveBusBridge",
    "publicEndpoint",
    "realCredentials",
    "deploy",
    "networkIntegration",
  ]) {
    if (config[field] !== false) {
      boundaryError(
        "LIVE_CAPABILITY_FORBIDDEN",
        `${field} must be explicitly false`,
      );
    }
  }

  if (
    !Array.isArray(config.identities) ||
    config.identities.length < 2 ||
    !config.identities.every(isSyntheticIdentity)
  ) {
    boundaryError(
      "IDENTITY_FORBIDDEN",
      "at least two synthetic resident labels are required",
    );
  }

  if (new Set(config.identities).size !== config.identities.length) {
    boundaryError("IDENTITY_DUPLICATE", "synthetic identities must be unique");
  }
  if (containsCredentialShape(config)) {
    boundaryError("CREDENTIAL_SHAPE_FORBIDDEN", "credential-shaped data detected");
  }

  return Object.freeze({
    ...config,
    identities: Object.freeze([...config.identities]),
  });
}

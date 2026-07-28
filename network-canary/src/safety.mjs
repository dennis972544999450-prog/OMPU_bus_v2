import { spawnSync } from "node:child_process";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";

const CREDENTIAL_BEGIN = ["BEGIN NATS", "USER JWT"].join(" ");
const CREDENTIAL_END = ["END USER", "NKEY SEED"].join(" ");
const CREDENTIAL_BLOCK = new RegExp(
  `-----${CREDENTIAL_BEGIN}-----[\\s\\S]*?-----${CREDENTIAL_END}-----`,
  "g",
);

const SECRET_PATTERNS = Object.freeze([
  ["nkey-seed", /\bS[A-Z2-7]{55}\b/],
  [
    "credentials-block",
    new RegExp([CREDENTIAL_BEGIN, CREDENTIAL_END].join("|")),
  ],
  ["raw-jwt", /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/],
  ["private-key", /-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----/],
  ["url-userinfo", /(?:nats|ws|wss):\/\/[^/@\s]+@/i],
  ["github-token", /\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}\b/],
]);

export function secretFindings(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return SECRET_PATTERNS.filter(([, pattern]) => pattern.test(text)).map(
    ([label]) => label,
  );
}

export function redactSensitiveText(value) {
  return String(value)
    .replace(CREDENTIAL_BLOCK, "<redacted-credentials>")
    .replace(/\bS[A-Z2-7]{55}\b/g, "<redacted-seed>")
    .replace(
      /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
      "<redacted-jwt>",
    )
    .replace(
      /-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:OPENSSH |RSA |EC )?PRIVATE KEY-----/g,
      "<redacted-private-key>",
    )
    .replace(/((?:nats|ws|wss):\/\/)[^/@\s]+@/gi, "$1")
    .slice(0, 800);
}

export function safeError(error) {
  const source = error instanceof Error ? error : new Error(String(error));
  return {
    name: source.name || "Error",
    code: typeof source.code === "string" ? source.code : null,
    message: redactSensitiveText(source.message),
  };
}

export function runCommand(binary, args, { cwd, env = process.env } = {}) {
  const result = spawnSync(binary, args, {
    cwd,
    env,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.status !== 0) {
    const output = redactSensitiveText(
      `${result.stdout || ""}\n${result.stderr || ""}`,
    );
    const error = new Error(
      `${binary} ${args[0] || ""} failed (${result.status}): ${output}`,
    );
    error.code = "COMMAND_FAILED";
    throw error;
  }
  return {
    stdout: result.stdout || "",
    stderr: result.stderr || "",
  };
}

export function assertSecretFree(value, label = "value") {
  const findings = secretFindings(value);
  if (findings.length > 0) {
    const error = new Error(
      `${label} contains forbidden material: ${findings.join(",")}`,
    );
    error.code = "SECRET_MATERIAL";
    throw error;
  }
}

export function writeBoundedJson(path, value, maxBytes = 32 * 1024) {
  assertSecretFree(value, "proof");
  const encoded = `${JSON.stringify(value, null, 2)}\n`;
  if (Buffer.byteLength(encoded) > maxBytes) {
    const error = new Error("proof exceeds bounded size");
    error.code = "PROOF_TOO_LARGE";
    throw error;
  }
  writeFileSync(path, encoded, { mode: 0o600 });
  chmodSync(path, 0o600);
}

export function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

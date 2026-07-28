import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import path from "node:path";

import { permissionArgs, userPermissions } from "./contracts.mjs";
import { runCommand } from "./safety.mjs";

function findNamedFile(root, predicate) {
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const candidate = path.join(root, entry.name);
    if (entry.isDirectory()) {
      const nested = findNamedFile(candidate, predicate);
      if (nested) {
        return nested;
      }
    } else if (entry.isFile() && predicate(candidate, entry.name)) {
      return candidate;
    }
  }
  return null;
}

function decodeJwtPayload(jwt) {
  const parts = jwt.trim().split(".");
  if (parts.length !== 3) {
    throw new Error("generated claim is not a JWT");
  }
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

function generatedJwt(home, account, user = null) {
  const suffix = user
    ? `${path.sep}accounts${path.sep}${account}${path.sep}users${path.sep}${user}.jwt`
    : `${path.sep}accounts${path.sep}${account}${path.sep}${account}.jwt`;
  const found = findNamedFile(home, (candidate) => candidate.endsWith(suffix));
  if (!found) {
    throw new Error(`generated JWT missing for ${account}/${user || "account"}`);
  }
  return found;
}

function publicClaim(pathname) {
  const payload = decodeJwtPayload(readFileSync(pathname, "utf8"));
  if (typeof payload.sub !== "string" || !payload.sub.startsWith("A")) {
    throw new Error("generated account claim has no public subject");
  }
  return {
    subject_sha256: createHash("sha256").update(payload.sub).digest("hex"),
    issuer_present: typeof payload.iss === "string",
  };
}

export function setupSyntheticTrust(runtimeRoot, nscBinary) {
  const home = path.join(runtimeRoot, "nsc");
  const credentialsRoot = path.join(runtimeRoot, "credentials");
  mkdirSync(home, { recursive: true, mode: 0o700 });
  mkdirSync(credentialsRoot, { recursive: true, mode: 0o700 });

  const nsc = (args) =>
    runCommand(nscBinary, ["-H", home, ...args], { cwd: runtimeRoot });

  const operatorName = "OMPU_NETWORK_CANARY";
  nsc(["add", "operator", "-n", operatorName, "-s", "--generate-signing-key"]);
  nsc(["delete", "user", "-a", "SYS", "-n", "sys", "--rm-creds", "--rm-nkey"]);

  nsc(["add", "account", "-n", "COMMONS"]);
  nsc(["edit", "account", "-n", "COMMONS", "--sk", "generate"]);
  nsc(["edit", "account", "-n", "COMMONS", "--js-disable"]);
  nsc(["edit", "account", "-n", "COMMONS", "--js-enable", "0"]);
  nsc([
    "edit",
    "account",
    "-n",
    "COMMONS",
    "--js-disk-storage",
    "64m",
    "--js-mem-storage",
    "0",
    "--js-streams",
    "1",
    "--js-consumer",
    "2",
  ]);

  const commonsJwtPath = generatedJwt(home, "COMMONS");
  const commonsPayload = decodeJwtPayload(readFileSync(commonsJwtPath, "utf8"));
  const commonsSigner = commonsPayload?.nats?.signing_keys?.[0];
  if (typeof commonsSigner !== "string") {
    throw new Error("COMMONS account signing key is missing");
  }

  const users = [
    { name: "fixture-bootstrap", kind: "bootstrap" },
    { name: "synthetic-resident-a", kind: "a" },
    { name: "synthetic-resident-b", kind: "b" },
  ];
  for (const user of users) {
    nsc([
      "-K",
      commonsSigner,
      "add",
      "user",
      "-a",
      "COMMONS",
      "-n",
      user.name,
      "--expiry",
      "10m",
      ...permissionArgs(userPermissions(user.kind)),
    ]);
  }

  const credentials = {};
  for (const user of users) {
    const target = path.join(credentialsRoot, `${user.name}.creds`);
    nsc([
      "generate",
      "creds",
      "-a",
      "COMMONS",
      "-n",
      user.name,
      "-o",
      target,
    ]);
    chmodSync(target, 0o600);
    credentials[user.kind] = target;
  }

  const resolverConfig = path.join(runtimeRoot, "resolver.generated.conf");
  nsc([
    "generate",
    "config",
    "--nats-resolver",
    "--sys-account",
    "SYS",
    "--config-file",
    resolverConfig,
    "--force",
  ]);
  const resolverRoot = path.join(runtimeRoot, "jwt");
  mkdirSync(resolverRoot, { recursive: true, mode: 0o700 });
  for (const account of ["SYS", "COMMONS"]) {
    const source = generatedJwt(home, account);
    const payload = decodeJwtPayload(readFileSync(source, "utf8"));
    if (typeof payload.sub !== "string" || !payload.sub.startsWith("A")) {
      throw new Error(`generated ${account} account has no public subject`);
    }
    const target = path.join(resolverRoot, `${payload.sub}.jwt`);
    copyFileSync(source, target);
    chmodSync(target, 0o600);
  }

  return {
    resolverConfig,
    credentials,
    proof: {
      operator: "synthetic",
      account: publicClaim(commonsJwtPath),
      users: users.map(({ kind }) => kind).sort(),
      resolver_accounts_loaded: 2,
      credentials_retained: false,
      credential_expiry: "10m",
    },
  };
}

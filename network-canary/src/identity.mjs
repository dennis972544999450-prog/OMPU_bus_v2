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

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
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

function publicUserClaim(pathname) {
  const payload = decodeJwtPayload(readFileSync(pathname, "utf8"));
  if (typeof payload.sub !== "string" || !payload.sub.startsWith("U")) {
    throw new Error("generated user claim has no public subject");
  }
  if (!Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)) {
    throw new Error("generated lifecycle user has no bounded lifetime");
  }
  return {
    subject: payload.sub,
    subject_sha256: createHash("sha256").update(payload.sub).digest("hex"),
    issued_at: payload.iat,
    expires_at: payload.exp,
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
    { name: "fixture-bootstrap", kind: "bootstrap", expiry: "10m" },
    { name: "synthetic-resident-a", kind: "a", expiry: "10m" },
    { name: "synthetic-resident-b", kind: "b", expiry: "10m" },
    {
      name: "synthetic-expiring",
      kind: "expiring",
      expiry: "1m",
    },
    { name: "synthetic-revocable", kind: "revocable", expiry: "10m" },
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
      user.expiry,
      ...permissionArgs(userPermissions(user.kind)),
    ]);
  }

  const credentials = {};
  const lifecycleClaims = {};
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
    lifecycleClaims[user.kind] = publicUserClaim(
      generatedJwt(home, "COMMONS", user.name),
    );
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
  let commonsResolverPath = null;
  for (const account of ["SYS", "COMMONS"]) {
    const source = generatedJwt(home, account);
    const payload = decodeJwtPayload(readFileSync(source, "utf8"));
    if (typeof payload.sub !== "string" || !payload.sub.startsWith("A")) {
      throw new Error(`generated ${account} account has no public subject`);
    }
    const target = path.join(resolverRoot, `${payload.sub}.jwt`);
    copyFileSync(source, target);
    chmodSync(target, 0o600);
    if (account === "COMMONS") {
      commonsResolverPath = target;
    }
  }
  if (!commonsResolverPath) {
    throw new Error("COMMONS resolver target was not created");
  }

  return {
    resolverConfig,
    credentials,
    control: {
      home,
      account_jwt_path: commonsJwtPath,
      resolver_account_jwt_path: commonsResolverPath,
      revocable_user: "synthetic-revocable",
      revocable_subject: lifecycleClaims.revocable.subject,
    },
    lifecycleClaims,
    proof: {
      operator: "synthetic",
      account: publicClaim(commonsJwtPath),
      users: users.map(({ kind }) => kind).sort(),
      resolver_accounts_loaded: 2,
      credentials_retained: false,
      credential_expiry: {
        ordinary: "10m",
        expiring: "1m",
        revocable: "10m",
      },
    },
  };
}

export function revokeSyntheticUser({
  nscBinary,
  home,
  accountJwtPath,
  resolverAccountJwtPath,
  userName,
  userSubject,
  userIssuedAt,
  serverUrl,
}) {
  if (userName !== "synthetic-revocable") {
    throw new Error("only the disposable revocable fixture may be revoked");
  }
  if (!/^nats:\/\/127\.0\.0\.1:\d{4,5}$/.test(serverUrl)) {
    throw new Error("revocation push target must be a loopback NATS URL");
  }
  if (
    typeof userSubject !== "string" ||
    !/^U[A-Z2-7]{55}$/.test(userSubject)
  ) {
    throw new Error("revocation fixture has no valid public user subject");
  }
  if (!Number.isSafeInteger(userIssuedAt)) {
    throw new Error("revocation fixture has no valid issued-at time");
  }
  const nsc = (args) =>
    runCommand(nscBinary, ["-H", home, ...args], { cwd: home });
  const beforeDigest = sha256(readFileSync(accountJwtPath));
  nsc([
    "revocations",
    "add-user",
    "-a",
    "COMMONS",
    "-n",
    userName,
  ]);
  const updatedJwt = readFileSync(accountJwtPath, "utf8");
  const updatedPayload = decodeJwtPayload(updatedJwt);
  const cutoff = updatedPayload?.nats?.revocations?.[userSubject];
  if (!Number.isSafeInteger(cutoff) || cutoff < userIssuedAt) {
    throw new Error("account JWT does not contain the expected revocation");
  }
  const afterDigest = sha256(updatedJwt);
  if (afterDigest === beforeDigest) {
    throw new Error("account JWT digest did not change after revocation");
  }
  nsc([
    "push",
    "-a",
    "COMMONS",
    "-u",
    serverUrl,
    "--timeout",
    "4",
  ]);
  const resolverDigest = sha256(readFileSync(resolverAccountJwtPath));
  if (resolverDigest !== afterDigest) {
    throw new Error("live resolver digest does not match the pushed account JWT");
  }
  return {
    revocation_written: true,
    account_update_pushed: true,
    cutoff_at_or_after_issue: true,
    account_jwt_changed: true,
    resolver_digest_matches: true,
    account_jwt_before_sha256: beforeDigest,
    account_jwt_after_sha256: afterDigest,
    resolver_jwt_sha256: resolverDigest,
    revocation_cutoff: cutoff,
    target: "loopback-nats-resolver",
  };
}

import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import { generateLocalTls } from "../src/certificates.mjs";
import { buildServerConfig } from "../src/contracts.mjs";
import {
  revokeSyntheticUser,
  setupSyntheticTrust,
} from "../src/identity.mjs";
import { assessLifecycleRejection } from "../src/lifecycle-evidence.mjs";
import { NETWORK_ROOT, resolveNetworkPath } from "../src/paths.mjs";
import {
  cleanupRuntime,
  createDisposableRuntime,
  reserveLoopbackPort,
  startServer,
  waitForFile,
  waitForPort,
  waitForProcessExit,
} from "../src/runtime.mjs";
import {
  assertSecretFree,
  readJson,
  redactSensitiveText,
  runCommand,
  safeError,
  writeBoundedJson,
} from "../src/safety.mjs";
import { installPinnedTools } from "../src/toolchain.mjs";

const runtime = createDisposableRuntime();
const startedAt = new Date().toISOString();
let clientProof = null;
let identityProof = null;
let lifecycleProof = null;
let toolchainProof = null;
let tlsProof = null;
let tlsNegativeProof = null;
let errorProof = null;
let teardown = null;
let serverLogPath = null;

function logOffset(pathname) {
  return existsSync(pathname) ? statSync(pathname).size : 0;
}

function lifecycleLogExcerpt(pathname, offset) {
  if (!existsSync(pathname)) {
    return "";
  }
  return redactSensitiveText(
    readFileSync(pathname)
      .subarray(offset)
      .toString("utf8")
      .split("\n")
      .filter((line) => /auth|expired|expiration|revok|violation/i.test(line))
      .slice(-24)
      .join("\n"),
  );
}

function lifecycleChildConfig({
  mode,
  kind,
  credentialsPath,
  attemptId,
  label,
  resultPath,
  readyPath = null,
  wssUrl,
}) {
  return {
    mode,
    kind,
    credentialsPath,
    attemptId,
    label,
    resultPath,
    readyPath,
    timeoutMs: 80_000,
    wssUrl,
  };
}

function lifecycleChildEnv(config, caCert) {
  return {
    ...process.env,
    NODE_EXTRA_CA_CERTS: caCert,
    NODE_TLS_REJECT_UNAUTHORIZED: "1",
    OMPU_NETWORK_LIFECYCLE_CLIENT: JSON.stringify(config),
  };
}

async function startAwaitCloseFixture({
  runtime,
  kind,
  credentialsPath,
  attemptId,
  label,
  resultPath,
  readyPath,
  wssUrl,
  caCert,
  serverLog,
}) {
  const offset = logOffset(serverLog);
  const child = spawn(
    process.execPath,
    [resolveNetworkPath("scripts", "lifecycle-client.mjs")],
    {
      cwd: NETWORK_ROOT,
      env: lifecycleChildEnv(
        lifecycleChildConfig({
          mode: "await-close",
          kind,
          credentialsPath,
          attemptId,
          label,
          resultPath,
          readyPath,
          wssUrl,
        }),
        caCert,
      ),
      stdio: ["ignore", "ignore", "ignore"],
    },
  );
  runtime.children.push(child);
  await waitForFile(readyPath, child, 8_000);
  const ready = readJson(readyPath);
  if (ready.attempt_id !== attemptId || ready.ready !== true) {
    throw new Error("lifecycle ready marker is not bound to its attempt");
  }
  return {
    child,
    attemptId,
    ready,
    resultPath,
    logOffset: offset,
  };
}

async function finishAwaitCloseFixture({
  handle,
  kind,
  expectedActorSha256,
  actorPublicKey,
  requireServerActor,
  controlBound = false,
  notBeforeEpochSeconds = null,
  serverLog,
}) {
  if (!(await waitForProcessExit(handle.child, 90_000))) {
    const error = new Error(`${kind} fixture did not exit before deadline`);
    error.code = "LIFECYCLE_CLIENT_TIMEOUT";
    throw error;
  }
  if (handle.child.exitCode !== 0) {
    const error = new Error(`${kind} fixture exited nonzero`);
    error.code = "LIFECYCLE_CLIENT_FAILED";
    throw error;
  }
  if (!existsSync(handle.resultPath)) {
    const error = new Error(`${kind} fixture exited without a result`);
    error.code = "LIFECYCLE_RESULT_MISSING";
    throw error;
  }
  const clientResult = readJson(handle.resultPath);
  const serverExcerpt = lifecycleLogExcerpt(serverLog, handle.logOffset);
  const timeControlBound =
    Number.isSafeInteger(notBeforeEpochSeconds) &&
    handle.ready.ready_at < notBeforeEpochSeconds &&
    Math.floor(Date.now() / 1000) >= notBeforeEpochSeconds;
  return {
    client: clientResult,
    evidence: assessLifecycleRejection({
      kind,
      phase: "active-close",
      attemptId: handle.attemptId,
      expectedActorSha256,
      actorPublicKey,
      requireServerActor,
      controlBound: controlBound || timeControlBound,
      clientResult,
      serverExcerpt,
    }),
  };
}

function runRejectedFixture({
  kind,
  credentialsPath,
  label,
  resultPath,
  wssUrl,
  caCert,
  expectedActorSha256,
  actorPublicKey,
  requireServerActor,
  controlBound = false,
  serverLog,
}) {
  const offset = logOffset(serverLog);
  const attemptId = randomUUID();
  const child = spawnSync(
    process.execPath,
    [resolveNetworkPath("scripts", "lifecycle-client.mjs")],
    {
      cwd: NETWORK_ROOT,
      env: lifecycleChildEnv(
        lifecycleChildConfig({
          mode: "expect-rejected",
          kind,
          credentialsPath,
          attemptId,
          label,
          resultPath,
          wssUrl,
        }),
        caCert,
      ),
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      timeout: 12_000,
    },
  );
  if (child.status !== 0) {
    const error = new Error(
      `${kind} reconnect fixture failed: ${redactSensitiveText(
        child.stderr || child.stdout || "",
      )}`,
    );
    error.code = "LIFECYCLE_RECONNECT_CLIENT_FAILED";
    throw error;
  }
  if (!existsSync(resultPath)) {
    const error = new Error(`${kind} reconnect fixture exited without a result`);
    error.code = "LIFECYCLE_RESULT_MISSING";
    throw error;
  }
  const clientResult = readJson(resultPath);
  const serverExcerpt = lifecycleLogExcerpt(serverLog, offset);
  return {
    client: clientResult,
    evidence: assessLifecycleRejection({
      kind,
      phase: "fresh-connect",
      attemptId,
      expectedActorSha256,
      actorPublicKey,
      requireServerActor,
      controlBound,
      clientResult,
      serverExcerpt,
    }),
  };
}

function runHealthyControl({
  credentialsPath,
  label,
  resultPath,
  wssUrl,
  caCert,
  expectedActorSha256,
}) {
  const attemptId = randomUUID();
  const child = spawnSync(
    process.execPath,
    [resolveNetworkPath("scripts", "lifecycle-client.mjs")],
    {
      cwd: NETWORK_ROOT,
      env: lifecycleChildEnv(
        lifecycleChildConfig({
          mode: "expect-connected",
          credentialsPath,
          attemptId,
          label,
          resultPath,
          wssUrl,
        }),
        caCert,
      ),
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      timeout: 12_000,
    },
  );
  if (child.status !== 0) {
    const error = new Error(
      `healthy control failed: ${redactSensitiveText(
        child.stderr || child.stdout || "",
      )}`,
    );
    error.code = "LIFECYCLE_HEALTHY_CONTROL_FAILED";
    throw error;
  }
  if (!existsSync(resultPath)) {
    const error = new Error("healthy control exited without a result");
    error.code = "LIFECYCLE_RESULT_MISSING";
    throw error;
  }
  const result = readJson(resultPath);
  return {
    pass:
      result.pass === true &&
      result.outcome === "connected-and-flushed" &&
      result.attempt_id === attemptId &&
      result.actor_subject_sha256 === expectedActorSha256,
    attempt_bound: result.attempt_id === attemptId,
    actor_bound: result.actor_subject_sha256 === expectedActorSha256,
    outcome: result.outcome,
  };
}

function publicLifecycleClaim(claim) {
  return {
    subject_sha256: claim.subject_sha256,
    issued_at: claim.issued_at,
    expires_at: claim.expires_at,
  };
}

try {
  const tools = await installPinnedTools(runtime.root);
  toolchainProof = tools.proof;
  const tls = generateLocalTls(runtime.root);
  tlsProof = tls.proof;
  const trust = setupSyntheticTrust(runtime.root, tools.nscBinary);
  identityProof = trust.proof;

  const clientPort = await reserveLoopbackPort();
  const wssPort = await reserveLoopbackPort();
  runtime.ports.push(clientPort, wssPort);
  const storeDir = path.join(runtime.root, "jetstream");
  mkdirSync(storeDir, { recursive: true, mode: 0o700 });
  const serverConfig = path.join(runtime.root, "server.conf");
  const serverLog = path.join(runtime.root, "server.log");
  serverLogPath = serverLog;
  const resolverConfig = readFileSync(trust.resolverConfig, "utf8");
  writeFileSync(
    serverConfig,
    buildServerConfig(resolverConfig, {
      clientPort,
      wssPort,
      certFile: tls.serverCert,
      keyFile: tls.serverKey,
      storeDir,
    }),
    { mode: 0o600 },
  );
  runCommand(tools.natsServerBinary, ["-t", "-c", serverConfig], {
    cwd: runtime.root,
  });
  runtime.server = startServer(
    tools.natsServerBinary,
    serverConfig,
    runtime.root,
    serverLog,
  );
  await waitForPort(wssPort, runtime.server);

  const openssl = process.env.OMPU_OPENSSL || "openssl";
  const tlsNegative = spawnSync(
    openssl,
    [
      "s_client",
      "-connect",
      `localhost:${wssPort}`,
      "-servername",
      "localhost",
      "-verify_return_error",
      "-brief",
    ],
    {
      cwd: NETWORK_ROOT,
      env: { ...process.env },
      input: "",
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      timeout: 15_000,
    },
  );
  const tlsNegativeDiagnostic = redactSensitiveText(
    `${tlsNegative.stdout || ""}\n${tlsNegative.stderr || ""}`,
  );
  const certificateRejectionObserved =
    tlsNegative.status !== 0 &&
    /certificate verify error|self.signed|unable to get local issuer|unknown ca/i.test(
      tlsNegativeDiagnostic,
    );
  if (!certificateRejectionObserved) {
    const error = new Error(
      `negative TLS control did not produce an explicit certificate rejection: ${tlsNegativeDiagnostic}`,
    );
    error.code = "TLS_NEGATIVE_CONTROL_FAILED";
    throw error;
  }
  tlsNegativeProof = {
    pass: true,
    trusted_ca_supplied: false,
    connection_established: false,
    certificate_rejection_observed: true,
    verifier: "openssl-s_client",
  };
  assertSecretFree(tlsNegativeProof, "negative TLS proof");

  const resultPath = path.join(runtime.root, "client-result.json");
  const childConfig = {
    wssUrl: `wss://localhost:${wssPort}`,
    bootstrapCredentials: trust.credentials.bootstrap,
    aCredentials: trust.credentials.a,
    bCredentials: trust.credentials.b,
    resultPath,
  };
  const child = spawnSync(
    process.execPath,
    [resolveNetworkPath("scripts", "wss-client.mjs")],
    {
      cwd: NETWORK_ROOT,
      env: {
        ...process.env,
        NODE_EXTRA_CA_CERTS: tls.caCert,
        NODE_TLS_REJECT_UNAUTHORIZED: "1",
        OMPU_NETWORK_CANARY_CLIENT: JSON.stringify(childConfig),
      },
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
      timeout: 120_000,
    },
  );
  if (child.status !== 0) {
    const error = new Error(
      `WSS client failed (${child.status}): ${child.stderr || child.stdout}`,
    );
    error.code = "WSS_CLIENT_FAILED";
    throw error;
  }
  clientProof = readJson(resultPath);
  assertSecretFree(clientProof, "client proof");

  const wssUrl = `wss://localhost:${wssPort}`;
  const expiryClaim = trust.lifecycleClaims.expiring;
  const expiryHandle = await startAwaitCloseFixture({
    runtime,
    kind: "expiry",
    credentialsPath: trust.credentials.expiring,
    attemptId: randomUUID(),
    label: "synthetic-expiring",
    resultPath: path.join(runtime.root, "expiry-close-result.json"),
    readyPath: path.join(runtime.root, "expiry-ready.json"),
    wssUrl,
    caCert: tls.caCert,
    serverLog,
  });
  const expiryClosed = await finishAwaitCloseFixture({
    handle: expiryHandle,
    kind: "expiry",
    expectedActorSha256: trust.lifecycleClaims.expiring.subject_sha256,
    actorPublicKey: trust.lifecycleClaims.expiring.subject,
    requireServerActor: false,
    notBeforeEpochSeconds: expiryClaim.expires_at,
    serverLog,
  });
  const expiryControlBound =
    expiryClosed.client.pass &&
    expiryClosed.evidence.pass &&
    Math.floor(Date.now() / 1000) >= expiryClaim.expires_at;
  const expiryReconnect = runRejectedFixture({
    kind: "expiry",
    credentialsPath: trust.credentials.expiring,
    label: "synthetic-expiring-reconnect",
    resultPath: path.join(runtime.root, "expiry-reconnect-result.json"),
    wssUrl,
    caCert: tls.caCert,
    expectedActorSha256: trust.lifecycleClaims.expiring.subject_sha256,
    actorPublicKey: trust.lifecycleClaims.expiring.subject,
    requireServerActor: false,
    controlBound: expiryControlBound,
    serverLog,
  });
  const expiryHealthyControl = runHealthyControl({
    credentialsPath: trust.credentials.b,
    label: "expiry-healthy-control",
    resultPath: path.join(runtime.root, "expiry-healthy-control.json"),
    wssUrl,
    caCert: tls.caCert,
    expectedActorSha256: trust.lifecycleClaims.b.subject_sha256,
  });
  const expiryProof = {
    pass:
      expiryClosed.client.pass &&
      expiryClosed.evidence.pass &&
      expiryReconnect.client.pass &&
      expiryReconnect.evidence.pass &&
      expiryHealthyControl.pass &&
      expiryControlBound &&
      expiryHandle.ready.ready_at < expiryClaim.expires_at &&
      Math.floor(Date.now() / 1000) >= expiryClaim.expires_at,
    claim: publicLifecycleClaim(expiryClaim),
    ready_before_expiry: expiryHandle.ready.ready_at < expiryClaim.expires_at,
    clock_after_expiry:
      Math.floor(Date.now() / 1000) >= expiryClaim.expires_at,
    connected_then_closed: expiryClosed,
    reconnect_denied: expiryReconnect,
    healthy_control: expiryHealthyControl,
  };
  lifecycleProof = {
    pass: false,
    expiry: expiryProof,
    revocation: null,
  };

  const revocationHandle = await startAwaitCloseFixture({
    runtime,
    kind: "revocation",
    credentialsPath: trust.credentials.revocable,
    attemptId: randomUUID(),
    label: "synthetic-revocable",
    resultPath: path.join(runtime.root, "revocation-close-result.json"),
    readyPath: path.join(runtime.root, "revocation-ready.json"),
    wssUrl,
    caCert: tls.caCert,
    serverLog,
  });
  const revocationControl = revokeSyntheticUser({
    nscBinary: tools.nscBinary,
    home: trust.control.home,
    accountJwtPath: trust.control.account_jwt_path,
    resolverAccountJwtPath: trust.control.resolver_account_jwt_path,
    userName: trust.control.revocable_user,
    userSubject: trust.control.revocable_subject,
    userIssuedAt: trust.lifecycleClaims.revocable.issued_at,
    serverUrl: `nats://127.0.0.1:${clientPort}`,
  });
  const revocationControlBound =
    revocationControl.revocation_written &&
    revocationControl.account_update_pushed &&
    revocationControl.cutoff_at_or_after_issue &&
    revocationControl.account_jwt_changed &&
    revocationControl.resolver_digest_matches;
  const revocationClosed = await finishAwaitCloseFixture({
    handle: revocationHandle,
    kind: "revocation",
    expectedActorSha256: trust.lifecycleClaims.revocable.subject_sha256,
    actorPublicKey: trust.lifecycleClaims.revocable.subject,
    requireServerActor: true,
    controlBound: revocationControlBound,
    serverLog,
  });
  const revocationReconnect = runRejectedFixture({
    kind: "revocation",
    credentialsPath: trust.credentials.revocable,
    label: "synthetic-revocable-reconnect",
    resultPath: path.join(runtime.root, "revocation-reconnect-result.json"),
    wssUrl,
    caCert: tls.caCert,
    expectedActorSha256: trust.lifecycleClaims.revocable.subject_sha256,
    actorPublicKey: trust.lifecycleClaims.revocable.subject,
    requireServerActor: true,
    controlBound: revocationControlBound,
    serverLog,
  });
  const revocationHealthyControl = runHealthyControl({
    credentialsPath: trust.credentials.b,
    label: "revocation-healthy-control",
    resultPath: path.join(runtime.root, "revocation-healthy-control.json"),
    wssUrl,
    caCert: tls.caCert,
    expectedActorSha256: trust.lifecycleClaims.b.subject_sha256,
  });
  const revocationProof = {
    pass:
      revocationControlBound &&
      revocationClosed.client.pass &&
      revocationClosed.evidence.pass &&
      revocationReconnect.client.pass &&
      revocationReconnect.evidence.pass &&
      revocationHealthyControl.pass,
    control: revocationControl,
    claim: publicLifecycleClaim(trust.lifecycleClaims.revocable),
    connected_then_closed: revocationClosed,
    reconnect_denied: revocationReconnect,
    healthy_control: revocationHealthyControl,
  };

  lifecycleProof = {
    pass: expiryProof.pass && revocationProof.pass,
    expiry: expiryProof,
    revocation: revocationProof,
  };
  assertSecretFree(lifecycleProof, "lifecycle proof");
  if (!lifecycleProof.pass) {
    const error = new Error(
      "JWT expiry/revocation lifecycle did not satisfy the canary contract",
    );
    error.code = "LIFECYCLE_GATE_FAILED";
    throw error;
  }
} catch (error) {
  errorProof = safeError(error);
  if (serverLogPath && existsSync(serverLogPath)) {
    errorProof.server_excerpt = redactSensitiveText(
      readFileSync(serverLogPath, "utf8")
        .split("\n")
        .filter((line) => /auth|permission|violation|error/i.test(line))
        .slice(-24)
        .join("\n"),
    );
  }
} finally {
  teardown = await cleanupRuntime(runtime);
}

const proof = {
  schema: "ompu.bus2.network-canary.v0.1",
  status:
    clientProof?.pass === true &&
    lifecycleProof?.pass === true &&
    teardown?.pass === true &&
    !errorProof
      ? "PASS"
      : "FAIL",
  started_at: startedAt,
  finished_at: new Date().toISOString(),
  boundary: {
    synthetic_only: true,
    loopback_only: true,
    bus_1_touched: false,
    public_endpoint_created: false,
    external_resident_enrolled: false,
    credentials_retained: false,
  },
  toolchain: toolchainProof,
  identity: identityProof,
  tls: tlsProof
    ? {
        ...tlsProof,
        negative_control: tlsNegativeProof,
      }
    : null,
  network: clientProof,
  lifecycle: lifecycleProof,
  teardown,
  error: errorProof,
};
assertSecretFree(proof, "network proof");
mkdirSync(resolveNetworkPath("proof"), { recursive: true, mode: 0o700 });
writeBoundedJson(resolveNetworkPath("proof", "latest.json"), proof);
process.stdout.write(`${JSON.stringify(proof, null, 2)}\n`);

if (proof.status !== "PASS") {
  process.exitCode = 1;
}

import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import { generateLocalTls } from "../src/certificates.mjs";
import { buildServerConfig } from "../src/contracts.mjs";
import { setupSyntheticTrust } from "../src/identity.mjs";
import { NETWORK_ROOT, resolveNetworkPath } from "../src/paths.mjs";
import {
  cleanupRuntime,
  createDisposableRuntime,
  reserveLoopbackPort,
  startServer,
  waitForPort,
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
let toolchainProof = null;
let tlsProof = null;
let tlsNegativeProof = null;
let errorProof = null;
let teardown = null;
let serverLogPath = null;

try {
  const tools = await installPinnedTools(runtime.root);
  toolchainProof = tools.proof;
  const tls = generateLocalTls(runtime.root);
  tlsProof = tls.proof;
  const trust = setupSyntheticTrust(runtime.root, tools.nscBinary);

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
    clientProof?.pass === true && teardown?.pass === true && !errorProof
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
  tls: tlsProof
    ? {
        ...tlsProof,
        negative_control: tlsNegativeProof,
      }
    : null,
  network: clientProof,
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

import { spawn } from "node:child_process";
import {
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  rmSync,
} from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

const PREFIX = "ompu-bus2-network-";

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function createDisposableRuntime() {
  const root = mkdtempSync(path.join(tmpdir(), PREFIX));
  chmodSync(root, 0o700);
  return {
    root,
    server: null,
    children: [],
    ports: [],
  };
}

export async function reserveLoopbackPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(
      { host: "127.0.0.1", port: 0, exclusive: true },
      resolve,
    );
  });
  const address = server.address();
  const port =
    typeof address === "object" && address ? address.port : undefined;
  await new Promise((resolve) => server.close(resolve));
  if (!Number.isSafeInteger(port)) {
    throw new Error("failed to reserve a loopback port");
  }
  return port;
}

export async function portOpen(port, timeout = 200) {
  return await new Promise((resolve) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    const finish = (value) => {
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(timeout, () => finish(false));
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
  });
}

export async function waitForPort(port, child, timeout = 10_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error("nats-server exited before opening the WSS listener");
    }
    if (await portOpen(port)) {
      return;
    }
    await delay(75);
  }
  throw new Error("WSS listener did not open before deadline");
}

export async function waitForProcessExit(child, timeout) {
  if (!child || child.exitCode !== null || child.signalCode !== null) {
    return true;
  }
  return await new Promise((resolve) => {
    const onExit = () => {
      clearTimeout(timer);
      resolve(true);
    };
    const timer = setTimeout(() => {
      child.removeListener("exit", onExit);
      resolve(false);
    }, timeout);
    child.once("exit", onExit);
  });
}

export async function stopTrackedProcess(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) {
    return true;
  }
  child.kill("SIGTERM");
  if (!(await waitForProcessExit(child, 4_000))) {
    child.kill("SIGKILL");
    await waitForProcessExit(child, 2_000);
  }
  return child.exitCode !== null || child.signalCode !== null;
}

export async function waitForFile(pathname, child, timeout = 10_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (existsSync(pathname)) {
      return;
    }
    if (
      child &&
      (child.exitCode !== null || child.signalCode !== null)
    ) {
      throw new Error("tracked process exited before writing its marker");
    }
    await delay(50);
  }
  throw new Error("tracked process did not write its marker before deadline");
}

function assertDisposableRoot(root) {
  const expectedParent = path.resolve(tmpdir());
  if (
    path.dirname(path.resolve(root)) !== expectedParent ||
    !path.basename(root).startsWith(PREFIX)
  ) {
    const error = new Error("runtime root is outside the disposable boundary");
    error.code = "RUNTIME_ROOT_FORBIDDEN";
    throw error;
  }
}

export async function cleanupRuntime(runtime) {
  assertDisposableRoot(runtime.root);
  const childResults = [];
  for (const child of runtime.children || []) {
    childResults.push(await stopTrackedProcess(child));
  }
  const serverExited = await stopTrackedProcess(runtime.server);
  const processExited =
    serverExited && childResults.every(Boolean);
  const listenerResults = [];
  for (const port of runtime.ports) {
    const deadline = Date.now() + 3_000;
    while (Date.now() < deadline && (await portOpen(port))) {
      await delay(75);
    }
    listenerResults.push(!(await portOpen(port)));
  }
  rmSync(runtime.root, { recursive: true, force: true });
  const runtimeRemoved = !existsSync(runtime.root);
  return {
    process_exited: processExited,
    child_processes_exited: childResults.every(Boolean),
    listeners_closed: listenerResults.every(Boolean),
    runtime_removed: runtimeRemoved,
    credentials_removed: runtimeRemoved,
    tools_removed: runtimeRemoved,
    pass:
      processExited &&
      listenerResults.every(Boolean) &&
      runtimeRemoved,
  };
}

export function startServer(binary, configPath, runtimeRoot, logPath) {
  mkdirSync(path.dirname(logPath), { recursive: true, mode: 0o700 });
  const descriptor = openSync(logPath, "a", 0o600);
  try {
    return spawn(binary, ["-c", configPath], {
      cwd: runtimeRoot,
      stdio: ["ignore", descriptor, descriptor],
      env: { ...process.env },
    });
  } finally {
    closeSync(descriptor);
  }
}

import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import { resolveNetworkPath } from "./paths.mjs";
import { runCommand } from "./safety.mjs";

const manifest = JSON.parse(
  readFileSync(resolveNetworkPath("toolchain.json"), "utf8"),
);

function sha256File(candidate) {
  return createHash("sha256").update(readFileSync(candidate)).digest("hex");
}

function findNamedFile(root, name) {
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const candidate = path.join(root, entry.name);
    if (entry.isDirectory()) {
      const nested = findNamedFile(candidate, name);
      if (nested) {
        return nested;
      }
    } else if (entry.isFile() && entry.name === name) {
      return candidate;
    }
  }
  return null;
}

function validateAsset(asset, prefix) {
  if (
    !asset ||
    typeof asset.asset !== "string" ||
    typeof asset.url !== "string" ||
    !asset.url.startsWith(prefix) ||
    !/^[a-f0-9]{64}$/.test(asset.sha256)
  ) {
    throw new Error("toolchain asset mapping is invalid");
  }
}

export function validateToolchainManifest(candidate = manifest) {
  if (
    candidate.schema !== "ompu.bus2.network-toolchain.v0.1" ||
    candidate.nats_server_version !== "2.14.3" ||
    candidate.nsc_version !== "2.15.0"
  ) {
    throw new Error("toolchain manifest versions are not pinned");
  }
  const expectedTargets = [
    "darwin-arm64",
    "darwin-x64",
    "linux-arm64",
    "linux-x64",
  ];
  if (
    JSON.stringify(Object.keys(candidate.targets).sort()) !==
    JSON.stringify(expectedTargets)
  ) {
    throw new Error("toolchain target matrix is incomplete");
  }
  for (const target of expectedTargets) {
    validateAsset(
      candidate.targets[target].nats_server,
      "https://github.com/nats-io/nats-server/releases/download/v2.14.3/",
    );
    validateAsset(
      candidate.targets[target].nsc,
      "https://github.com/nats-io/nsc/releases/download/v2.15.0/",
    );
  }
  return true;
}

export function selectToolchain({
  platform = process.platform,
  arch = process.arch,
} = {}) {
  validateToolchainManifest();
  const target = `${platform}-${arch}`;
  const selected = manifest.targets[target];
  if (!selected) {
    const error = new Error(`unsupported network canary target: ${target}`);
    error.code = "UNSUPPORTED_NETWORK_TARGET";
    throw error;
  }
  return {
    target,
    natsServerVersion: manifest.nats_server_version,
    nscVersion: manifest.nsc_version,
    natsServer: { ...selected.nats_server },
    nsc: { ...selected.nsc },
  };
}

async function downloadVerified(asset, destination) {
  const response = await fetch(asset.url, { redirect: "follow" });
  if (!response.ok) {
    throw new Error(`official asset download failed: HTTP ${response.status}`);
  }
  const declaredLength = Number(response.headers.get("content-length") || 0);
  if (declaredLength > 100 * 1024 * 1024) {
    throw new Error("official asset exceeds bounded download size");
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length === 0 || bytes.length > 100 * 1024 * 1024) {
    throw new Error("official asset has an invalid size");
  }
  writeFileSync(destination, bytes, { mode: 0o600 });
  const observed = sha256File(destination);
  if (observed !== asset.sha256) {
    const error = new Error(`asset checksum mismatch for ${asset.asset}`);
    error.code = "ASSET_CHECKSUM_MISMATCH";
    throw error;
  }
  return observed;
}

export async function installPinnedTools(runtimeRoot) {
  const selected = selectToolchain();
  const toolsRoot = path.join(runtimeRoot, "tools");
  const archivesRoot = path.join(toolsRoot, "archives");
  const natsRoot = path.join(toolsRoot, "nats-server");
  const nscRoot = path.join(toolsRoot, "nsc");
  for (const directory of [toolsRoot, archivesRoot, natsRoot, nscRoot]) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
  }

  const natsArchive = path.join(archivesRoot, selected.natsServer.asset);
  const nscArchive = path.join(archivesRoot, selected.nsc.asset);
  const natsHash = await downloadVerified(selected.natsServer, natsArchive);
  const nscHash = await downloadVerified(selected.nsc, nscArchive);

  runCommand("tar", ["-xzf", natsArchive, "-C", natsRoot], {
    cwd: runtimeRoot,
  });
  runCommand("unzip", ["-q", nscArchive, "-d", nscRoot], {
    cwd: runtimeRoot,
  });

  const natsServerBinary = findNamedFile(natsRoot, "nats-server");
  const nscBinary = findNamedFile(nscRoot, "nsc");
  if (
    !natsServerBinary ||
    !nscBinary ||
    !statSync(natsServerBinary).isFile() ||
    !statSync(nscBinary).isFile()
  ) {
    throw new Error("verified archives did not contain expected executables");
  }
  chmodSync(natsServerBinary, 0o700);
  chmodSync(nscBinary, 0o700);

  const natsVersion = runCommand(natsServerBinary, ["--version"]).stdout.trim();
  const nscVersion = runCommand(nscBinary, ["--version"]).stdout.trim();
  if (!natsVersion.includes(`v${selected.natsServerVersion}`)) {
    throw new Error("nats-server binary version does not match manifest");
  }
  if (!nscVersion.includes(selected.nscVersion)) {
    throw new Error("nsc binary version does not match manifest");
  }

  return {
    natsServerBinary,
    nscBinary,
    proof: {
      target: selected.target,
      nats_server: {
        version: selected.natsServerVersion,
        asset: selected.natsServer.asset,
        sha256: natsHash,
        verified: true,
      },
      nsc: {
        version: selected.nscVersion,
        asset: selected.nsc.asset,
        sha256: nscHash,
        verified: true,
      },
    },
  };
}

import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));

export const NETWORK_ROOT = realpathSync(path.resolve(MODULE_DIR, ".."));
export const PROJECT_ROOT = realpathSync(path.resolve(NETWORK_ROOT, ".."));

export function resolveNetworkPath(...segments) {
  const candidate = path.resolve(NETWORK_ROOT, ...segments);
  const relative = path.relative(NETWORK_ROOT, candidate);
  if (
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    const error = new Error("path escapes network-canary root");
    error.code = "NETWORK_PATH_ESCAPE";
    throw error;
  }
  return candidate;
}

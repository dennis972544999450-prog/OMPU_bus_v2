import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));

export const PROJECT_ROOT = realpathSync(path.resolve(MODULE_DIR, ".."));

export function assertInsideProject(candidatePath) {
  const resolved = path.resolve(candidatePath);
  const relative = path.relative(PROJECT_ROOT, resolved);
  const isInside =
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative));

  if (!isInside) {
    const error = new Error("path escapes the portability candidate root");
    error.code = "OUTSIDE_PROJECT";
    throw error;
  }

  return resolved;
}

export function resolveInsideProject(...segments) {
  return assertInsideProject(path.join(PROJECT_ROOT, ...segments));
}

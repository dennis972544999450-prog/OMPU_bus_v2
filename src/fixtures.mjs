import { readFileSync } from "node:fs";

import { resolveInsideProject } from "./project-root.mjs";
import { assertSyntheticBoundary } from "./security-boundary.mjs";
import { validateEvent } from "./event.mjs";

export function loadSyntheticBoundary() {
  const path = resolveInsideProject("fixtures", "transport.json");
  return assertSyntheticBoundary(JSON.parse(readFileSync(path, "utf8")));
}

export function loadSyntheticEvents() {
  const path = resolveInsideProject("fixtures", "events.jsonl");
  return readFileSync(path, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => validateEvent(JSON.parse(line)));
}

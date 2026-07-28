import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { PROJECT_ROOT } from "../src/project-root.mjs";

function run(command, args, cwd, env) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    process.stderr.write(result.stdout);
    process.stderr.write(result.stderr);
    throw new Error(
      `${command} ${args.join(" ")} failed with status ${result.status}`,
    );
  }
}

const temporaryRoot = mkdtempSync(
  path.join(tmpdir(), "ompu-bus2-portability-"),
);
const copyRoot = path.join(temporaryRoot, "arbitrary-copy");
const home = path.join(temporaryRoot, "home");
const cache = path.join(temporaryRoot, "npm-cache");

try {
  cpSync(PROJECT_ROOT, copyRoot, {
    recursive: true,
    filter(source) {
      const relative = path.relative(PROJECT_ROOT, source);
      return ![
        ".git",
        "node_modules",
        ".npm",
        "coverage",
        "proof",
        "runtime",
      ].some(
        (blocked) =>
          relative === blocked || relative.startsWith(`${blocked}${path.sep}`),
      );
    },
  });
  mkdirSync(home, { recursive: true });
  mkdirSync(cache, { recursive: true });

  const env = {
    ...process.env,
    HOME: home,
    npm_config_cache: cache,
    npm_config_audit: "false",
    npm_config_fund: "false",
    npm_config_ignore_scripts: "true",
    npm_config_update_notifier: "false",
  };

  run(
    "npm",
    ["ci", "--no-audit", "--no-fund", "--ignore-scripts"],
    copyRoot,
    env,
  );
  run("npm", ["test"], copyRoot, env);
  run("npm", ["run", "verify"], copyRoot, env);

  console.log(
    JSON.stringify(
      {
        schema: "ompu.bus2.cold-copy-verification.v0.1",
        status: "PASS",
        copiedToArbitraryPath: true,
        sourceTreeMutated: false,
        externalResident: "HOLD",
      },
      null,
      2,
    ),
  );
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true });
}

import { PROJECT_ROOT } from "./project-root.mjs";
import { selectPlatform } from "./platform.mjs";

const RUNNER_MODULES = Object.freeze({
  darwin: "./runners/darwin.mjs",
  linux: "./runners/linux.mjs",
});

export async function buildRunnerPlan(options = {}) {
  const platform = selectPlatform(options);
  const modulePath = RUNNER_MODULES[platform.runner];

  if (!modulePath) {
    const error = new Error(`runner module is not registered: ${platform.runner}`);
    error.code = "RUNNER_NOT_REGISTERED";
    throw error;
  }

  const runner = await import(modulePath);
  return runner.createRunnerPlan(platform, PROJECT_ROOT);
}

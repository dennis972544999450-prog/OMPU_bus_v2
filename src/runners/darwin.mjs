export function createRunnerPlan(platform, projectRoot) {
  return Object.freeze({
    schema: "ompu.bus2.runner-plan.v0.1",
    runner: "darwin-loopback-plan",
    platform: platform.platform,
    arch: platform.arch,
    projectRoot,
    execution: "plan-only",
    isolation: platform.isolation,
    network: Object.freeze({
      mode: "disabled",
      listener: null,
      tls: false,
      wss: false,
    }),
    syntheticOnly: true,
    externalResident: "HOLD",
    executables: platform.executables,
    nscAsset: platform.nscAsset,
  });
}

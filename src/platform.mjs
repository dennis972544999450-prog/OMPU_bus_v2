const PLATFORM_MATRIX = Object.freeze({
  "darwin-arm64": Object.freeze({
    runner: "darwin",
    nscAsset: "nsc-darwin-arm64.zip",
    isolation: "sandbox-exec-optional",
  }),
  "darwin-x64": Object.freeze({
    runner: "darwin",
    nscAsset: "nsc-darwin-amd64.zip",
    isolation: "sandbox-exec-optional",
  }),
  "linux-arm64": Object.freeze({
    runner: "linux",
    nscAsset: "nsc-linux-arm64.zip",
    isolation: "container-or-network-namespace-required",
  }),
  "linux-x64": Object.freeze({
    runner: "linux",
    nscAsset: "nsc-linux-amd64.zip",
    isolation: "container-or-network-namespace-required",
  }),
});

export function selectPlatform({
  platform = process.platform,
  arch = process.arch,
  env = process.env,
} = {}) {
  const selected = PLATFORM_MATRIX[`${platform}-${arch}`];

  if (!selected) {
    const error = new Error(`unsupported portability target: ${platform}-${arch}`);
    error.code = "UNSUPPORTED_PLATFORM";
    throw error;
  }

  return Object.freeze({
    platform,
    arch,
    runner: selected.runner,
    nscAsset: selected.nscAsset,
    isolation: selected.isolation,
    executables: Object.freeze({
      natsServer: env.OMPU_NATS_SERVER || "nats-server",
      nsc: env.OMPU_NSC || "nsc",
    }),
  });
}

export function supportedTargets() {
  return Object.keys(PLATFORM_MATRIX).sort();
}

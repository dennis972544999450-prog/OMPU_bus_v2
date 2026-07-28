export const STREAM = "COMMONS";
export const SUBJECT_A = "commons.synthetic-resident-a";
export const SUBJECT_B = "commons.synthetic-resident-b";
export const DURABLE_A = "SYNTHETIC_A";
export const DURABLE_B = "SYNTHETIC_B";

export function userPermissions(kind) {
  if (kind === "bootstrap") {
    return {
      pub: [
        "$JS.API.INFO",
        `$JS.API.STREAM.CREATE.${STREAM}`,
        `$JS.API.STREAM.INFO.${STREAM}`,
        `$JS.API.CONSUMER.CREATE.${STREAM}.${DURABLE_A}.>`,
        `$JS.API.CONSUMER.CREATE.${STREAM}.${DURABLE_B}.>`,
        `$JS.API.CONSUMER.DURABLE.CREATE.${STREAM}.${DURABLE_A}`,
        `$JS.API.CONSUMER.DURABLE.CREATE.${STREAM}.${DURABLE_B}`,
        `$JS.API.CONSUMER.INFO.${STREAM}.${DURABLE_A}`,
        `$JS.API.CONSUMER.INFO.${STREAM}.${DURABLE_B}`,
      ],
      sub: ["_INBOX.OMPU.NET.BOOTSTRAP.>"],
    };
  }
  if (kind === "a") {
    return {
      pub: [
        SUBJECT_A,
        "$JS.API.INFO",
        `$JS.API.STREAM.INFO.${STREAM}`,
        `$JS.API.CONSUMER.INFO.${STREAM}.${DURABLE_A}`,
        `$JS.API.CONSUMER.MSG.NEXT.${STREAM}.${DURABLE_A}`,
        `$JS.ACK.${STREAM}.${DURABLE_A}.>`,
      ],
      sub: ["_INBOX.OMPU.NET.A.>"],
    };
  }
  if (kind === "b") {
    return {
      pub: [
        SUBJECT_B,
        "$JS.API.INFO",
        `$JS.API.STREAM.INFO.${STREAM}`,
        `$JS.API.CONSUMER.INFO.${STREAM}.${DURABLE_B}`,
        `$JS.API.CONSUMER.MSG.NEXT.${STREAM}.${DURABLE_B}`,
        `$JS.ACK.${STREAM}.${DURABLE_B}.>`,
      ],
      sub: ["_INBOX.OMPU.NET.B.>"],
    };
  }
  throw new Error(`unknown permission kind: ${kind}`);
}

export function permissionArgs(permission) {
  const args = [];
  for (const subject of permission.pub) {
    args.push("--allow-pub", subject);
  }
  for (const subject of permission.sub) {
    args.push("--allow-sub", subject);
  }
  return args;
}

export function buildServerConfig(
  resolverConfig,
  {
    clientPort,
    wssPort,
    certFile,
    keyFile,
    storeDir,
  },
) {
  for (const port of [clientPort, wssPort]) {
    if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
      throw new Error("canary port is outside the allowed ephemeral range");
    }
  }

  return `${resolverConfig.trim()}
server_name: "ompu-network-canary"
listen: ${JSON.stringify(`127.0.0.1:${clientPort}`)}
websocket {
  listen: ${JSON.stringify(`127.0.0.1:${wssPort}`)}
  same_origin: false
  no_tls: false
  tls {
    cert_file: ${JSON.stringify(certFile)}
    key_file: ${JSON.stringify(keyFile)}
    min_version: "1.2"
    timeout: 2
  }
}
jetstream {
  store_dir: ${JSON.stringify(storeDir)}
  max_memory_store: 64MB
  max_file_store: 64MB
}
`;
}

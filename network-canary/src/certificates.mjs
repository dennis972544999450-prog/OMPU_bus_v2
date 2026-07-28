import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import { runCommand } from "./safety.mjs";

function sha256File(candidate) {
  return createHash("sha256").update(readFileSync(candidate)).digest("hex");
}

export function generateLocalTls(runtimeRoot) {
  const tlsRoot = path.join(runtimeRoot, "tls");
  mkdirSync(tlsRoot, { recursive: true, mode: 0o700 });

  const caConfig = path.join(tlsRoot, "ca.cnf");
  const serverConfig = path.join(tlsRoot, "server.cnf");
  const caKey = path.join(tlsRoot, "ca.key");
  const caCert = path.join(tlsRoot, "ca.pem");
  const serverKey = path.join(tlsRoot, "server.key");
  const serverCsr = path.join(tlsRoot, "server.csr");
  const serverCert = path.join(tlsRoot, "server.pem");

  writeFileSync(
    caConfig,
    `[req]
distinguished_name = ca_dn
x509_extensions = ca_ext
prompt = no

[ca_dn]
CN = OMPU Synthetic Network Canary CA

[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
`,
    { mode: 0o600 },
  );
  writeFileSync(
    serverConfig,
    `[req]
distinguished_name = server_dn
req_extensions = server_ext
prompt = no

[server_dn]
CN = localhost

[server_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
`,
    { mode: 0o600 },
  );

  const openssl = process.env.OMPU_OPENSSL || "openssl";
  runCommand(
    openssl,
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-sha256",
      "-nodes",
      "-days",
      "1",
      "-config",
      caConfig,
      "-keyout",
      caKey,
      "-out",
      caCert,
    ],
    { cwd: tlsRoot },
  );
  runCommand(
    openssl,
    [
      "req",
      "-new",
      "-newkey",
      "rsa:2048",
      "-sha256",
      "-nodes",
      "-config",
      serverConfig,
      "-keyout",
      serverKey,
      "-out",
      serverCsr,
    ],
    { cwd: tlsRoot },
  );
  runCommand(
    openssl,
    [
      "x509",
      "-req",
      "-in",
      serverCsr,
      "-CA",
      caCert,
      "-CAkey",
      caKey,
      "-CAcreateserial",
      "-days",
      "1",
      "-sha256",
      "-extfile",
      serverConfig,
      "-extensions",
      "server_ext",
      "-out",
      serverCert,
    ],
    { cwd: tlsRoot },
  );
  runCommand(openssl, ["verify", "-CAfile", caCert, serverCert], {
    cwd: tlsRoot,
  });

  chmodSync(caKey, 0o600);
  chmodSync(serverKey, 0o600);
  chmodSync(caCert, 0o600);
  chmodSync(serverCert, 0o600);

  return {
    caCert,
    serverCert,
    serverKey,
    proof: {
      local_ca: true,
      server_san_dns: "localhost",
      server_san_ip: "127.0.0.1",
      ca_cert_sha256: sha256File(caCert),
      server_cert_sha256: sha256File(serverCert),
      private_keys_retained: false,
    },
  };
}

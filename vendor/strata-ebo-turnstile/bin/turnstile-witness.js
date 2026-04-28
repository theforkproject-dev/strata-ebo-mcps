#!/usr/bin/env node
import { createServer } from "node:http";
import { loadOrCreateEd25519Signer, Witness } from "../src/index.js";

const args = parseArgs(process.argv.slice(2));
const witnessId = args["witness-id"] ?? process.env.WITNESS_ID ?? "witness-local";
const port = Number(args.port ?? process.env.PORT ?? 9001);
const host = args.host ?? process.env.HOST ?? "127.0.0.1";
const keyFile = args["key-file"] ?? process.env.WITNESS_KEY_FILE ?? `artifacts/witnesses/${witnessId}.key.json`;
const walPath = args.wal ?? process.env.WITNESS_WAL ?? `artifacts/witnesses/${witnessId}.wal.jsonl`;

const { signer, publicKeyPem } = loadOrCreateEd25519Signer({
  keyFile,
  keyId: args["key-id"] ?? process.env.WITNESS_KEY_ID ?? `witness:${witnessId}`,
  keyJson: args["key-json"] ?? process.env.WITNESS_KEY_JSON,
  privateKeyPem: args["private-key-pem"] ?? process.env.WITNESS_PRIVATE_KEY_PEM,
  publicKeyPem: args["public-key-pem"] ?? process.env.WITNESS_PUBLIC_KEY_PEM
});
const witness = new Witness({ id: witnessId, signer, walPath });

const server = createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/health") {
      return json(response, 200, { ok: true, witness_id: witnessId });
    }

    if (request.method === "GET" && request.url === "/v1/public-key") {
      return json(response, 200, {
        witness_id: witnessId,
        key_id: signer.keyId,
        public_key_pem: publicKeyPem
      });
    }

    if (request.method === "POST" && request.url === "/v1/sign") {
      const body = await readJson(request);
      if (!body.subject) {
        return json(response, 400, { error: "subject is required" });
      }

      try {
        return json(response, 200, { signature: witness.sign(body.subject) });
      } catch (error) {
        const status = /refuses equivocation/.test(error.message) ? 409 : 400;
        return json(response, status, { error: error.message });
      }
    }

    json(response, 404, { error: "not found" });
  } catch (error) {
    json(response, 500, { error: error.message });
  }
});

server.listen(port, host, () => {
  const address = server.address();
  const actualPort = typeof address === "object" ? address.port : port;
  console.log(JSON.stringify({
    ok: true,
    witness_id: witnessId,
    url: `http://${host === "0.0.0.0" ? "127.0.0.1" : host}:${actualPort}`,
    key_id: signer.keyId,
    public_key_pem: publicKeyPem,
    key_file: keyFile,
    wal_path: walPath
  }));
});

async function readJson(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw.length === 0 ? {} : JSON.parse(raw);
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) {
      continue;
    }
    parsed[item.slice(2)] = argv[index + 1];
    index += 1;
  }
  return parsed;
}

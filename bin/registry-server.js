#!/usr/bin/env node
import { createServer } from "node:http";
import { loadConfig } from "../src/config.js";
import { buildEmailRegistryEpoch, loadRegistrySigner, REGISTRY_EPOCH_ID } from "../src/registry/email-registry.js";

const config = loadConfig();
const signer = loadRegistrySigner({
  keyFile: process.env.REGISTRY_KEY_FILE || "artifacts/registry/registry-authority.key.json",
  keyId: process.env.REGISTRY_KEY_ID || "registry-authority:email-demo"
});

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${config.host}:${config.port}`);
    if (request.method === "GET" && url.pathname === "/health") {
      return json(response, 200, { ok: true, registry_id: "strata-email-demo-registry", epoch_id: REGISTRY_EPOCH_ID });
    }
    if (request.method === "GET" && url.pathname === "/registry/public-key") {
      return json(response, 200, { key_id: signer.signer.keyId, public_key_pem: signer.publicKeyPem });
    }
    if (request.method === "GET" && (url.pathname === "/registry/current" || url.pathname === `/registry/epochs/${REGISTRY_EPOCH_ID}`)) {
      const binding = await buildEmailRegistryEpoch({
        mechanicalWitnesses: config.witnesses,
        policyWitnesses: config.policyWitnesses,
        signer: { keyId: signer.signer.keyId, privateKey: signer.signer.privateKey, publicKeyPem: signer.publicKeyPem }
      });
      return json(response, 200, binding.epoch);
    }
    return json(response, 404, { error: "not found" });
  } catch (error) {
    return json(response, 500, { error: error.message });
  }
});

server.listen(config.port, config.host, () => {
  console.log(JSON.stringify({ ok: true, url: `http://${config.host}:${config.port}`, registry_key_id: signer.signer.keyId }));
});

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

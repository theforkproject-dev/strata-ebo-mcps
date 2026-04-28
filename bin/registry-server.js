#!/usr/bin/env node
import { createServer } from "node:http";
import { loadConfig } from "../src/config.js";
import {
  buildEmailPolicyPointer,
  buildEmailRegistryEpoch,
  loadRegistrySigner,
  REGISTRY_EPOCH_ID,
  REGISTRY_ID
} from "../src/registry/email-registry.js";
import { loadEmailPolicyBundle, policyBundleDigest } from "../src/policy/email-policy.js";

const config = loadConfig();
const signer = loadRegistrySigner({
  keyFile: process.env.REGISTRY_KEY_FILE || "artifacts/registry/registry-authority.key.json",
  keyId: process.env.REGISTRY_KEY_ID || "registry-authority:email-demo"
});
const policyBundle = await loadEmailPolicyBundle({
  file: process.env.POLICY_BUNDLE_FILE || config.policy.bundleFile,
  url: process.env.POLICY_BUNDLE_SOURCE_URL || ""
});
const policyUrl = process.env.POLICY_BUNDLE_URL || `${config.publicBaseUrl}/policies/epochs/${policyBundle.epoch_id}`;
const policyDigest = policyBundleDigest(policyBundle);

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${config.host}:${config.port}`);
    if (request.method === "GET" && url.pathname === "/health") {
      return json(response, 200, {
        ok: true,
        registry_id: REGISTRY_ID,
        epoch_id: REGISTRY_EPOCH_ID,
        active_policy_epoch_id: policyBundle.epoch_id,
        active_policy_digest: policyDigest,
        active_policy_url: policyUrl
      });
    }
    if (request.method === "GET" && url.pathname === "/registry/public-key") {
      return json(response, 200, { key_id: signer.signer.keyId, public_key_pem: signer.publicKeyPem });
    }
    if (request.method === "GET" && (url.pathname === "/registry/current" || url.pathname === `/registry/epochs/${REGISTRY_EPOCH_ID}`)) {
      const binding = await buildEmailRegistryEpoch({
        mechanicalWitnesses: config.witnesses,
        policyWitnesses: config.policyWitnesses,
        signer: { keyId: signer.signer.keyId, privateKey: signer.signer.privateKey, publicKeyPem: signer.publicKeyPem },
        policyBundle,
        policyUrl
      });
      return json(response, 200, binding.epoch);
    }
    if (request.method === "GET" && url.pathname === "/policies/current") {
      return json(response, 200, buildEmailPolicyPointer({
        policyBundle,
        policyUrl,
        signer: { keyId: signer.signer.keyId, privateKey: signer.signer.privateKey }
      }));
    }
    if (request.method === "GET" && url.pathname === `/policies/epochs/${policyBundle.epoch_id}`) {
      return json(response, 200, policyBundle);
    }
    return json(response, 404, { error: "not found" });
  } catch (error) {
    return json(response, 500, { error: error.message });
  }
});

server.listen(config.port, config.host, () => {
  console.log(JSON.stringify({
    ok: true,
    url: `http://${config.host === "0.0.0.0" ? "127.0.0.1" : config.host}:${config.port}`,
    registry_key_id: signer.signer.keyId,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_digest: policyDigest,
    policy_url: policyUrl
  }));
});

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

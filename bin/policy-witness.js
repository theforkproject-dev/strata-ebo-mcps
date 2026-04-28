#!/usr/bin/env node
import { createServer } from "node:http";
import { loadOrCreateEd25519Signer } from "../src/strata/primitives.js";
import {
  createPolicyDecisionSubject,
  defaultEmailPolicyBundle,
  policyBundleDigest,
  signPolicyDecisionSubject
} from "../src/policy/email-policy.js";

const args = parseArgs(process.argv.slice(2));
const witnessId = args["witness-id"] || process.env.POLICY_WITNESS_ID || process.env.WITNESS_ID || "policy-witness-local";
const port = Number(args.port || process.env.PORT || 9201);
const host = args.host || process.env.HOST || "127.0.0.1";
const keyFile = args["key-file"] || process.env.POLICY_WITNESS_KEY_FILE || `artifacts/policy-witnesses/${witnessId}.key.json`;
const keyId = args["key-id"] || process.env.POLICY_WITNESS_KEY_ID || `policy-witness:${witnessId}`;
const policyBundle = defaultEmailPolicyBundle();
const policyDigest = policyBundleDigest(policyBundle);
const { signer, publicKeyPem } = loadOrCreateEd25519Signer({ keyFile, keyId });

const server = createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/health") {
      return json(response, 200, { ok: true, witness_id: witnessId, tier: "policy", policy_epoch_id: policyBundle.epoch_id });
    }

    if (request.method === "GET" && request.url === "/v1/public-key") {
      return json(response, 200, { witness_id: witnessId, key_id: signer.keyId, public_key_pem: publicKeyPem });
    }

    if (request.method === "GET" && request.url === "/v1/policy") {
      return json(response, 200, { policy_bundle: policyBundle, policy_bundle_digest: policyDigest });
    }

    if (request.method === "POST" && request.url === "/v1/evaluate") {
      const body = await readJson(request);
      if (!body.email || !body.commitment) {
        return json(response, 400, { error: "email and commitment are required" });
      }
      if (body.policy_bundle_digest && body.policy_bundle_digest !== policyDigest) {
        return json(response, 409, { error: "policy_bundle_digest mismatch", policy_bundle_digest: policyDigest });
      }
      const subject = createPolicyDecisionSubject({
        witnessId,
        policyBundle,
        email: body.email,
        commitment: body.commitment
      });
      return json(response, 200, {
        subject,
        signature: signPolicyDecisionSubject(subject, signer),
        policy_bundle_digest: policyDigest
      });
    }

    return json(response, 404, { error: "not found" });
  } catch (error) {
    return json(response, 500, { error: error.message });
  }
});

server.listen(port, host, () => {
  console.log(JSON.stringify({
    ok: true,
    witness_id: witnessId,
    url: `http://${host === "0.0.0.0" ? "127.0.0.1" : host}:${port}`,
    key_id: signer.keyId,
    public_key_pem: publicKeyPem,
    policy_bundle_digest: policyDigest,
    policy_epoch_id: policyBundle.epoch_id
  }));
});

async function readJson(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
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

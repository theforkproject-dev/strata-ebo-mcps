#!/usr/bin/env node
import { createServer } from "node:http";
import { loadConfig } from "../src/config.js";
import { loadOrCreateEd25519Signer } from "../src/strata/primitives.js";
import {
  createPolicyDecisionSubject,
  loadEmailPolicyBundle,
  policyBundleDigest,
  signPolicyDecisionSubject
} from "../src/policy/email-policy.js";
import {
  createSupabasePolicyDecisionSubject,
  defaultSupabasePolicyBundle,
  signSupabasePolicyDecisionSubject,
  supabasePolicyBundleDigest
} from "../src/policy/supabase-policy.js";
import {
  KOJIMEM_POLICY_DOMAIN,
  createKojimemPolicyDecisionSubject,
  defaultKojimemPolicyBundle,
  signKojimemPolicyDecisionSubject,
  kojimemPolicyBundleDigest
} from "../src/policy/kojimem-policy.js";
import {
  MANAGED_AGENT_POLICY_DOMAIN,
  createManagedAgentPolicyDecisionSubject,
  defaultManagedAgentPolicyBundle,
  managedAgentPolicyBundleDigest,
  signManagedAgentPolicyDecisionSubject
} from "../src/policy/managed-agent-policy.js";

const args = parseArgs(process.argv.slice(2));
const witnessId = args["witness-id"] || process.env.POLICY_WITNESS_ID || process.env.WITNESS_ID || "policy-witness-local";
const port = Number(args.port || process.env.PORT || 9201);
const host = args.host || process.env.HOST || "127.0.0.1";
const keyFile = args["key-file"] || process.env.POLICY_WITNESS_KEY_FILE || `artifacts/policy-witnesses/${witnessId}.key.json`;
const keyId = args["key-id"] || process.env.POLICY_WITNESS_KEY_ID || `policy-witness:${witnessId}`;
const policyUrl = args["policy-url"] || process.env.POLICY_BUNDLE_URL || "";
const config = loadConfig();
const emailPolicyBundle = await loadEmailPolicyBundle({
  file: args["policy-file"] || process.env.POLICY_BUNDLE_FILE,
  url: policyUrl
});
const emailPolicyDigest = policyBundleDigest(emailPolicyBundle);
const supabasePolicyBundle = defaultSupabasePolicyBundle(config);
const supabasePolicyDigest = supabasePolicyBundleDigest(supabasePolicyBundle);
const supabasePolicyUrl = args["supabase-policy-url"] || process.env.SUPABASE_POLICY_BUNDLE_URL || "";
const kojimemPolicyBundle = defaultKojimemPolicyBundle(config);
const kojimemPolicyDigest = kojimemPolicyBundleDigest(kojimemPolicyBundle);
const kojimemPolicyUrl = args["kojimem-policy-url"] || process.env.KOJIMEM_POLICY_BUNDLE_URL || "";
const managedAgentPolicyBundle = defaultManagedAgentPolicyBundle();
const managedAgentPolicyDigest = managedAgentPolicyBundleDigest(managedAgentPolicyBundle);
const managedAgentPolicyUrl = args["managed-agent-policy-url"] || process.env.MANAGED_AGENT_POLICY_BUNDLE_URL || "";
const { signer, publicKeyPem } = loadOrCreateEd25519Signer({ keyFile, keyId });

const SUPPORTED_POLICY_DOMAINS = ["policy.email.send", "policy.supabase.mcp", KOJIMEM_POLICY_DOMAIN, MANAGED_AGENT_POLICY_DOMAIN];

const server = createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/health") {
      return json(response, 200, {
        ok: true,
        witness_id: witnessId,
        tier: "policy",
        policy_epoch_id: emailPolicyBundle.epoch_id,
        policy_bundle_digest: emailPolicyDigest,
        policy_url: policyUrl || null,
        supported_policy_domains: SUPPORTED_POLICY_DOMAINS,
        policies: {
          email: {
            policy_epoch_id: emailPolicyBundle.epoch_id,
            policy_bundle_digest: emailPolicyDigest,
            policy_url: policyUrl || null
          },
          supabase: {
            policy_epoch_id: supabasePolicyBundle.epoch_id,
            policy_bundle_digest: supabasePolicyDigest,
            policy_url: supabasePolicyUrl || null
          },
          kojimem: {
            policy_epoch_id: kojimemPolicyBundle.epoch_id,
            policy_bundle_digest: kojimemPolicyDigest,
            policy_url: kojimemPolicyUrl || null
          },
          managed_agent: {
            policy_epoch_id: managedAgentPolicyBundle.epoch_id,
            policy_bundle_digest: managedAgentPolicyDigest,
            policy_url: managedAgentPolicyUrl || null
          }
        }
      });
    }

    if (request.method === "GET" && request.url === "/v1/public-key") {
      return json(response, 200, { witness_id: witnessId, key_id: signer.keyId, public_key_pem: publicKeyPem });
    }

    if (request.method === "GET" && request.url === "/v1/policy") {
      return json(response, 200, { policy_bundle: emailPolicyBundle, policy_bundle_digest: emailPolicyDigest, policy_url: policyUrl || null });
    }

    if (request.method === "GET" && request.url === "/v1/policies") {
      return json(response, 200, {
        email: { policy_bundle: emailPolicyBundle, policy_bundle_digest: emailPolicyDigest, policy_url: policyUrl || null },
        supabase: { policy_bundle: supabasePolicyBundle, policy_bundle_digest: supabasePolicyDigest, policy_url: supabasePolicyUrl || null },
        kojimem: { policy_bundle: kojimemPolicyBundle, policy_bundle_digest: kojimemPolicyDigest, policy_url: kojimemPolicyUrl || null },
        managed_agent: { policy_bundle: managedAgentPolicyBundle, policy_bundle_digest: managedAgentPolicyDigest, policy_url: managedAgentPolicyUrl || null }
      });
    }

    if (request.method === "POST" && request.url === "/v1/evaluate") {
      const body = await readJson(request);
      if (body.domain === "policy.supabase.mcp" || body.request?.version === "strata.supabase.request.v1") {
        return evaluateSupabase(response, body);
      }
      if (body.domain === KOJIMEM_POLICY_DOMAIN || body.request?.version === "strata.kojimem.agent_handoff_request.v1") {
        return evaluateKojimem(response, body);
      }
      if (body.domain === MANAGED_AGENT_POLICY_DOMAIN || body.request?.version === "attexa.managed_agent.action_request.v1") {
        return evaluateManagedAgent(response, body);
      }
      if (!body.email || !body.commitment) {
        return json(response, 400, { error: "email and commitment are required" });
      }
      if (body.policy_bundle_digest && body.policy_bundle_digest !== emailPolicyDigest) {
        return json(response, 409, { error: "policy_bundle_digest mismatch", policy_bundle_digest: emailPolicyDigest });
      }
      if (body.policy_epoch_id && body.policy_epoch_id !== emailPolicyBundle.epoch_id) {
        return json(response, 409, { error: "policy_epoch_id mismatch", policy_epoch_id: emailPolicyBundle.epoch_id });
      }
      if (policyUrl && body.policy_url && body.policy_url !== policyUrl) {
        return json(response, 409, { error: "policy_url mismatch", policy_url: policyUrl });
      }
      const subject = createPolicyDecisionSubject({
        witnessId,
        policyBundle: emailPolicyBundle,
        policyUrl: body.policy_url || policyUrl,
        email: body.email,
        commitment: body.commitment
      });
      return json(response, 200, {
        subject,
        signature: signPolicyDecisionSubject(subject, signer),
        policy_bundle_digest: emailPolicyDigest,
        policy_url: body.policy_url || policyUrl || null
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
    policy_bundle_digest: emailPolicyDigest,
    policy_epoch_id: emailPolicyBundle.epoch_id,
    policy_url: policyUrl || null,
    supported_policy_domains: SUPPORTED_POLICY_DOMAINS,
    supabase_policy_bundle_digest: supabasePolicyDigest,
    supabase_policy_epoch_id: supabasePolicyBundle.epoch_id,
    kojimem_policy_bundle_digest: kojimemPolicyDigest,
    kojimem_policy_epoch_id: kojimemPolicyBundle.epoch_id,
    managed_agent_policy_bundle_digest: managedAgentPolicyDigest,
    managed_agent_policy_epoch_id: managedAgentPolicyBundle.epoch_id
  }));
});

function evaluateSupabase(response, body) {
  if (!body.tool_name || !body.request) {
    return json(response, 400, { error: "tool_name and request are required for Supabase policy evaluation" });
  }
  if (body.policy_bundle_digest && body.policy_bundle_digest !== supabasePolicyDigest) {
    return json(response, 409, { error: "policy_bundle_digest mismatch", policy_bundle_digest: supabasePolicyDigest });
  }
  if (body.policy_epoch_id && body.policy_epoch_id !== supabasePolicyBundle.epoch_id) {
    return json(response, 409, { error: "policy_epoch_id mismatch", policy_epoch_id: supabasePolicyBundle.epoch_id });
  }
  if (supabasePolicyUrl && body.policy_url && body.policy_url !== supabasePolicyUrl) {
    return json(response, 409, { error: "policy_url mismatch", policy_url: supabasePolicyUrl });
  }
  const subject = createSupabasePolicyDecisionSubject({
    witnessId,
    policyBundle: supabasePolicyBundle,
    policyUrl: body.policy_url || supabasePolicyUrl,
    toolName: body.tool_name,
    input: body.input || {},
    request: body.request,
    config
  });
  return json(response, 200, {
    subject,
    signature: signSupabasePolicyDecisionSubject(subject, signer),
    policy_bundle_digest: supabasePolicyDigest,
    policy_url: body.policy_url || supabasePolicyUrl || null
  });
}

function evaluateKojimem(response, body) {
  if (!body.request) {
    return json(response, 400, { error: "request is required for Kojimem policy evaluation" });
  }
  if (body.policy_bundle_digest && body.policy_bundle_digest !== kojimemPolicyDigest) {
    return json(response, 409, { error: "policy_bundle_digest mismatch", policy_bundle_digest: kojimemPolicyDigest });
  }
  if (body.policy_epoch_id && body.policy_epoch_id !== kojimemPolicyBundle.epoch_id) {
    return json(response, 409, { error: "policy_epoch_id mismatch", policy_epoch_id: kojimemPolicyBundle.epoch_id });
  }
  if (kojimemPolicyUrl && body.policy_url && body.policy_url !== kojimemPolicyUrl) {
    return json(response, 409, { error: "policy_url mismatch", policy_url: kojimemPolicyUrl });
  }
  const subject = createKojimemPolicyDecisionSubject({
    witnessId,
    policyBundle: kojimemPolicyBundle,
    policyUrl: body.policy_url || kojimemPolicyUrl,
    request: body.request,
    input: body.input || {},
    config
  });
  return json(response, 200, {
    subject,
    signature: signKojimemPolicyDecisionSubject(subject, signer),
    policy_bundle_digest: kojimemPolicyDigest,
    policy_url: body.policy_url || kojimemPolicyUrl || null
  });
}

function evaluateManagedAgent(response, body) {
  if (!body.request) {
    return json(response, 400, { error: "request is required for Managed Agent policy evaluation" });
  }
  if (body.policy_bundle_digest && body.policy_bundle_digest !== managedAgentPolicyDigest) {
    return json(response, 409, { error: "policy_bundle_digest mismatch", policy_bundle_digest: managedAgentPolicyDigest });
  }
  if (body.policy_epoch_id && body.policy_epoch_id !== managedAgentPolicyBundle.epoch_id) {
    return json(response, 409, { error: "policy_epoch_id mismatch", policy_epoch_id: managedAgentPolicyBundle.epoch_id });
  }
  if (managedAgentPolicyUrl && body.policy_url && body.policy_url !== managedAgentPolicyUrl) {
    return json(response, 409, { error: "policy_url mismatch", policy_url: managedAgentPolicyUrl });
  }
  const subject = createManagedAgentPolicyDecisionSubject({
    witnessId,
    policyBundle: managedAgentPolicyBundle,
    policyUrl: body.policy_url || managedAgentPolicyUrl,
    request: body.request
  });
  return json(response, 200, {
    subject,
    signature: signManagedAgentPolicyDecisionSubject(subject, signer),
    policy_bundle_digest: managedAgentPolicyDigest,
    policy_url: body.policy_url || managedAgentPolicyUrl || null
  });
}

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

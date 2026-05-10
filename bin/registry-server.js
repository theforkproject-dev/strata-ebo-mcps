#!/usr/bin/env node
import { createServer } from "node:http";
import { loadConfig } from "../src/config.js";
import {
  buildEmailPolicyPointer,
  buildEmailRegistryEpoch,
  defaultSupabasePolicyBundleMetadata,
  buildOperatorRegistryRecord,
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
const supabasePolicy = defaultSupabasePolicyBundleMetadata(config, process.env.SUPABASE_POLICY_BUNDLE_URL || "");
const authorizedWorkflows = parseCsv(process.env.REGISTRY_AUTHORIZED_WORKFLOWS || "email.send,supabase.query");
const authorizedTools = parseCsv(process.env.REGISTRY_AUTHORIZED_TOOLS || "email_send_verified,supabase-mcp,supabase_list_tables_verified,supabase_inspect_schema_verified,supabase_query_readonly_verified,supabase_search_docs");
const registryAuthoritySigner = { keyId: signer.signer.keyId, privateKey: signer.signer.privateKey, publicKeyPem: signer.publicKeyPem };

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
        active_policy_url: policyUrl,
        supabase_policy_epoch_id: supabasePolicy.policy_epoch_id,
        supabase_policy_digest: supabasePolicy.policy_bundle_digest,
        authorized_workflows: authorizedWorkflows,
        authorized_tools: authorizedTools,
        operator_registry_configured: Boolean(config.operator.admissionPublicKeyPem)
      });
    }
    if (request.method === "GET" && url.pathname === "/registry/public-key") {
      return json(response, 200, { key_id: signer.signer.keyId, public_key_pem: signer.publicKeyPem });
    }
    if (request.method === "GET" && (url.pathname === "/registry/current" || url.pathname === `/registry/epochs/${REGISTRY_EPOCH_ID}`)) {
      const binding = await buildEmailRegistryEpoch({
        mechanicalWitnesses: config.witnesses,
        policyWitnesses: config.policyWitnesses,
        signer: registryAuthoritySigner,
        policyBundle,
        policyUrl,
        additionalPolicyBundles: [supabasePolicy],
        authorizedWorkflows
      });
      return json(response, 200, binding.epoch);
    }
    if (request.method === "GET" && url.pathname === "/policies/current") {
      return json(response, 200, buildEmailPolicyPointer({
        policyBundle,
        policyUrl,
        signer: registryAuthoritySigner
      }));
    }
    if (request.method === "GET" && url.pathname === `/policies/epochs/${policyBundle.epoch_id}`) {
      return json(response, 200, policyBundle);
    }
    if (request.method === "GET" && (url.pathname === "/operators/current" || url.pathname.startsWith("/operators/"))) {
      const requestedOperatorId = url.pathname === "/operators/current"
        ? config.operator.id
        : decodeURIComponent(url.pathname.slice("/operators/".length));
      if (requestedOperatorId !== config.operator.id) {
        return json(response, 404, { error: "operator not found" });
      }
      if (!config.operator.admissionPublicKeyPem) {
        return json(response, 503, { error: "operator admission public key is not configured" });
      }
      return json(response, 200, buildOperatorRegistryRecord({
        operatorId: config.operator.id,
        tenantId: config.tenant.id,
        keyId: config.operator.admissionKeyId,
        publicKeyPem: config.operator.admissionPublicKeyPem,
        signer: registryAuthoritySigner,
        policyBundle,
        policyUrl,
        additionalPolicyBundles: [supabasePolicy],
        authorizedWorkflows,
        authorizedTools
      }));
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
    policy_url: policyUrl,
    supabase_policy_epoch_id: supabasePolicy.policy_epoch_id,
    supabase_policy_bundle_digest: supabasePolicy.policy_bundle_digest,
    authorized_workflows: authorizedWorkflows,
    authorized_tools: authorizedTools,
    operator_registry_configured: Boolean(config.operator.admissionPublicKeyPem)
  }));
});

function parseCsv(value) {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

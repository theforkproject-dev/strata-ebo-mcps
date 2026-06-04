import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { loadCertificateBundle } from "../src/certificates/bundle.js";
import { createKojimemActionRegistry } from "../src/strata/verified-kojimem.js";
import { createKojimemHandoffRequest } from "../src/kojimem/canonical.js";
import { defaultKojimemPolicyBundle, evaluateKojimemPolicy } from "../src/policy/kojimem-policy.js";
import { digestValue } from "../src/strata/primitives.js";

test("kojimem mode keeps separate gateway defaults and server-side wallets", () => {
  const config = testConfig();

  assert.equal(config.gatewayKind, "kojimem");
  assert.equal(config.dataDir, "artifacts/kojimem-agent-handoff");
  assert.equal(config.gateway.id, "gateway:kojimem-agent-handoff");
  assert.equal(config.gateway.keyId, "gateway:kojimem-agent-handoff");
  assert.equal(config.witness.signedRequests.workflowId, "agent-handoff.fraud-signal-exchange");
  assert.match(config.kojimem.agentAAccount.address, /^0x/);
  assert.match(config.kojimem.agentBAccount.address, /^0x/);
});

test("kojimem action registry exposes fraud signal exchange tool", async () => {
  const config = testConfig();
  const registry = await createKojimemActionRegistry(config);
  const tool = registry.tools.find((item) => item.name === "fraud_signal_exchange_verified");

  assert.ok(tool);
  assert.equal(registry.actions[0].assurance.mode, "witnessed-agentic-transaction");
  assert.equal(tool.inputSchema.properties.l3_attestation.type, "object");
});

test("kojimem policy requires L3 above exposure threshold", () => {
  const config = testConfig();
  const { request, executionInput } = createKojimemHandoffRequest({ estimated_exposure_usd: 25000 }, config);
  const policyBundle = defaultKojimemPolicyBundle(config);
  const decision = evaluateKojimemPolicy({ request, input: executionInput, config, policyBundle });

  assert.equal(decision.decision, "deny");
  assert.ok(decision.reasons.includes("l3_attestation_present"));
  assert.equal(decision.l3_required.claim_type, "fraud-data-release");
});

test("kojimem policy allows high exposure with bound L3 approval", () => {
  const config = testConfig();
  const base = createKojimemHandoffRequest({ estimated_exposure_usd: 25000 }, config);
  const attestation = {
    attestation_id: "dom_att_test",
    attestor_id: "fraud-data-steward:test",
    claim_type: "fraud-data-release",
    decision: "approve",
    request_digest: digestValue(base.request),
    issued_at: "2026-06-04T00:00:00Z",
    signature: { alg: "Ed25519", sig: "test", public_key: "test" }
  };
  const { request, executionInput } = createKojimemHandoffRequest({ estimated_exposure_usd: 25000, l3_attestation: attestation }, config);
  const decision = evaluateKojimemPolicy({ request, input: executionInput, config, policyBundle: defaultKojimemPolicyBundle(config) });

  assert.equal(decision.decision, "allow");
  assert.deepEqual(decision.reasons, []);
});

test("kojimem bundles use Kojimem bundle version", () => {
  const dir = mkdtempSync(join(tmpdir(), "kojimem-bundle-"));
  writeFileSync(join(dir, "certificate.json"), JSON.stringify({ version: "strata.kojimem.agent_handoff_certificate.v1" }));
  const bundle = loadCertificateBundle({
    config: { certificateBaseUrl: "https://kojimem.example.test/certificates" },
    runId: "kojimem_test",
    runDir: dir
  });

  assert.equal(bundle.version, "strata.kojimem.certificate_bundle.v1");
});

function testConfig() {
  return loadConfig({
    STRATA_GATEWAY_KIND: "kojimem",
    KOJIMEM_AGENT_A_PRIVATE_KEY: `0x${"11".repeat(32)}`,
    KOJIMEM_AGENT_B_PRIVATE_KEY: `0x${"22".repeat(32)}`,
    PUBLIC_BASE_URL: "https://kojimem.example.test",
    CERTIFICATE_BASE_URL: "https://kojimem.example.test/certificates",
    WITNESS_URLS: "w1=https://w1.example.test,w2=https://w2.example.test",
    POLICY_WITNESS_URLS: "p1=https://p1.example.test,p2=https://p2.example.test"
  });
}

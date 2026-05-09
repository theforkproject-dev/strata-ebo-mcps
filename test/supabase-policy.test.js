import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import {
  collectSupabasePolicyQuorum,
  createSupabasePolicyDecisionSubject,
  defaultSupabasePolicyBundle,
  signSupabasePolicyDecisionSubject,
  supabasePolicyBundleDigest,
  verifySupabasePolicyDecisionSubject
} from "../src/policy/supabase-policy.js";
import { canonicalSupabaseRequest } from "../src/supabase/canonical.js";

test("Supabase policy decision subjects sign and verify", () => {
  const config = testConfig();
  const policyBundle = defaultSupabasePolicyBundle(config);
  const request = testRequest(config);
  const signer = testSigner("policy-witness:p1:test");
  const subject = createSupabasePolicyDecisionSubject({
    witnessId: "p1",
    policyBundle,
    toolName: request.strata_tool_name,
    input: request.input,
    request,
    config,
    issuedAt: "2026-05-09T22:00:00.000Z"
  });
  const signature = signSupabasePolicyDecisionSubject(subject, signer);

  assert.equal(subject.version, "strata.supabase.policy_decision.v1");
  assert.equal(subject.domain, "policy.supabase.mcp");
  assert.equal(subject.decision, "allow");
  assert.equal(subject.policy_bundle_digest, supabasePolicyBundleDigest(policyBundle));
  assert.equal(verifySupabasePolicyDecisionSubject(subject, signature, signer.publicKeyPem).ok, true);
  assert.equal(verifySupabasePolicyDecisionSubject({ ...subject, decision: "deny" }, signature, signer.publicKeyPem).ok, false);
});

test("Supabase policy quorum collects signed allow decisions", async () => {
  const config = testConfig();
  const policyBundle = defaultSupabasePolicyBundle(config);
  const request = testRequest(config);
  const signers = [testSigner("policy-witness:p1:test"), testSigner("policy-witness:p2:test"), testSigner("policy-witness:p3:test")];
  const fetchImpl = fakePolicyWitnessFetch({ config, policyBundle, signers });

  const quorum = await collectSupabasePolicyQuorum({
    witnesses: signers.map((signer, index) => ({ id: `p${index + 1}`, url: `https://policy-${index + 1}.example.test` })),
    toolName: request.strata_tool_name,
    input: request.input,
    request,
    config,
    policyBundle,
    threshold: 2,
    fetchImpl
  });

  assert.equal(quorum.version, "strata.supabase.policy_quorum.v1");
  assert.equal(quorum.ok, true);
  assert.equal(quorum.decision, "allow");
  assert.equal(quorum.allow_count, 3);
  assert.equal(quorum.decisions.length, 3);
  assert.deepEqual(quorum.errors, []);
});

test("Supabase policy quorum denies when signed allow threshold is not met", async () => {
  const config = testConfig();
  const policyBundle = defaultSupabasePolicyBundle(config);
  const request = testRequest(config);
  const signers = [testSigner("policy-witness:p1:test"), testSigner("policy-witness:p2:test"), testSigner("policy-witness:p3:test")];
  const fetchImpl = fakePolicyWitnessFetch({ config, policyBundle, signers, failIndexes: new Set([1, 2]) });

  const quorum = await collectSupabasePolicyQuorum({
    witnesses: signers.map((signer, index) => ({ id: `p${index + 1}`, url: `https://policy-${index + 1}.example.test` })),
    toolName: request.strata_tool_name,
    input: request.input,
    request,
    config,
    policyBundle,
    threshold: 2,
    fetchImpl
  });

  assert.equal(quorum.ok, false);
  assert.equal(quorum.decision, "deny");
  assert.equal(quorum.allow_count, 1);
  assert.equal(quorum.errors.length, 2);
});

function fakePolicyWitnessFetch({ config, policyBundle, signers, failIndexes = new Set() }) {
  return async (url, options = {}) => {
    const index = Number(new URL(url).hostname.match(/policy-(\d+)/)?.[1] || 1) - 1;
    const signer = signers[index];
    if (url.endsWith("/v1/public-key")) {
      return jsonResponse(200, { witness_id: `p${index + 1}`, key_id: signer.keyId, public_key_pem: signer.publicKeyPem });
    }
    if (url.endsWith("/v1/evaluate")) {
      if (failIndexes.has(index)) {
        return jsonResponse(503, { error: "policy witness unavailable" });
      }
      const body = JSON.parse(options.body);
      const subject = createSupabasePolicyDecisionSubject({
        witnessId: `p${index + 1}`,
        policyBundle,
        toolName: body.tool_name,
        input: body.input,
        request: body.request,
        config,
        issuedAt: "2026-05-09T22:00:00.000Z"
      });
      return jsonResponse(200, {
        subject,
        signature: signSupabasePolicyDecisionSubject(subject, signer),
        policy_bundle_digest: supabasePolicyBundleDigest(policyBundle),
        policy_url: null
      });
    }
    return jsonResponse(404, { error: "not found" });
  };
}

function testRequest(config) {
  const input = { query: "select * from public.chat_sessions" };
  return canonicalSupabaseRequest({
    strataToolName: "supabase_query_readonly_verified",
    upstreamToolName: "execute_sql",
    upstreamArguments: { query: "select * from public.chat_sessions limit 100" },
    input,
    config
  });
}

function testConfig() {
  return {
    supabase: {
      connectorId: "heyjil-supabase-pilot",
      connectorLabel: "HeyJil Supabase Pilot",
      projectRef: "ghmfczkhbwfftvpsrghy",
      readOnly: true,
      features: ["database", "docs"],
      mcpBaseUrl: "https://mcp.supabase.com/mcp",
      evidenceMode: "digest-only",
      maxRows: 100,
      timeoutMs: 30000,
      blockedSchemas: ["auth", "storage", "vault"],
      blockedTables: [],
      oauth: {}
    }
  };
}

function testSigner(keyId) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    keyId,
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" })
  };
}

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    }
  };
}

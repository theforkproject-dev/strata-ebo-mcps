import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import {
  MANAGED_AGENT_POLICY_DECISION_VERSION,
  MANAGED_AGENT_POLICY_DOMAIN,
  collectManagedAgentPolicyQuorum,
  createManagedAgentPolicyDecisionSubject,
  defaultManagedAgentPolicyBundle,
  managedAgentPolicyBundleDigest,
  signManagedAgentPolicyDecisionSubject,
  verifyManagedAgentPolicyDecisionSubject
} from "../src/policy/managed-agent-policy.js";

test("Managed Agent policy decision subjects sign and verify", () => {
  const policyBundle = defaultManagedAgentPolicyBundle();
  const request = deniedWriteRequest();
  const signer = testSigner("policy-witness:p1:test");
  const subject = createManagedAgentPolicyDecisionSubject({
    witnessId: "p1",
    policyBundle,
    request,
    issuedAt: "2026-06-08T22:00:00.000Z"
  });
  const signature = signManagedAgentPolicyDecisionSubject(subject, signer);

  assert.equal(subject.version, MANAGED_AGENT_POLICY_DECISION_VERSION);
  assert.equal(subject.domain, MANAGED_AGENT_POLICY_DOMAIN);
  assert.equal(subject.decision, "deny");
  assert.equal(subject.policy_bundle_digest, managedAgentPolicyBundleDigest(policyBundle));
  assert.equal(verifyManagedAgentPolicyDecisionSubject(subject, signature, signer.publicKeyPem).ok, true);
  assert.equal(verifyManagedAgentPolicyDecisionSubject({ ...subject, decision: "allow" }, signature, signer.publicKeyPem).ok, false);
});

test("Managed Agent policy quorum collects signed deny decisions", async () => {
  const policyBundle = defaultManagedAgentPolicyBundle();
  const request = deniedWriteRequest();
  const signers = [testSigner("policy-witness:p1:test"), testSigner("policy-witness:p2:test"), testSigner("policy-witness:p3:test")];
  const fetchImpl = fakePolicyWitnessFetch({ policyBundle, signers });

  const quorum = await collectManagedAgentPolicyQuorum({
    witnesses: signers.map((signer, index) => ({ id: `p${index + 1}`, url: `https://policy-${index + 1}.example.test` })),
    request,
    policyBundle,
    threshold: 2,
    fetchImpl
  });

  assert.equal(quorum.version, "attexa.managed_agent.policy_quorum.v1");
  assert.equal(quorum.ok, false);
  assert.equal(quorum.decision, "deny");
  assert.equal(quorum.deny_count, 3);
  assert.equal(quorum.decisions.length, 3);
  assert.deepEqual(quorum.errors, []);
});

test("Managed Agent policy quorum allows safe output write", async () => {
  const policyBundle = defaultManagedAgentPolicyBundle();
  const request = {
    ...deniedWriteRequest(),
    event_id: "sevt_safe_write",
    input: { file_path: "/mnt/session/outputs/release-note.md", content: "ready\n" }
  };
  const signers = [testSigner("policy-witness:p1:test"), testSigner("policy-witness:p2:test"), testSigner("policy-witness:p3:test")];
  const fetchImpl = fakePolicyWitnessFetch({ policyBundle, signers });

  const quorum = await collectManagedAgentPolicyQuorum({
    witnesses: signers.map((signer, index) => ({ id: `p${index + 1}`, url: `https://policy-${index + 1}.example.test` })),
    request,
    policyBundle,
    threshold: 2,
    fetchImpl
  });

  assert.equal(quorum.ok, true);
  assert.equal(quorum.decision, "allow");
  assert.equal(quorum.allow_count, 3);
});

function fakePolicyWitnessFetch({ policyBundle, signers }) {
  return async (url, options = {}) => {
    const index = Number(new URL(url).hostname.match(/policy-(\d+)/)?.[1] || 1) - 1;
    const signer = signers[index];
    if (url.endsWith("/v1/public-key")) {
      return jsonResponse(200, { witness_id: `p${index + 1}`, key_id: signer.keyId, public_key_pem: signer.publicKeyPem });
    }
    if (url.endsWith("/v1/evaluate")) {
      const body = JSON.parse(options.body);
      const subject = createManagedAgentPolicyDecisionSubject({
        witnessId: `p${index + 1}`,
        policyBundle,
        request: body.request,
        issuedAt: "2026-06-08T22:00:00.000Z"
      });
      return jsonResponse(200, {
        subject,
        signature: signManagedAgentPolicyDecisionSubject(subject, signer),
        policy_bundle_digest: managedAgentPolicyBundleDigest(policyBundle),
        policy_url: null
      });
    }
    return jsonResponse(404, { error: "not found" });
  };
}

function deniedWriteRequest() {
  return {
    version: "attexa.managed_agent.action_request.v1",
    domain: MANAGED_AGENT_POLICY_DOMAIN,
    session_id: "sesn_test",
    profile_id: "document-producer",
    policy_mode: "governed",
    event_id: "sevt_write",
    event_type: "agent.tool_use",
    tool_name: "write",
    mcp_server_name: null,
    mcp_tool_name: "write",
    input: { file_path: "/workspace/release-note.md", content: "ready\n" }
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

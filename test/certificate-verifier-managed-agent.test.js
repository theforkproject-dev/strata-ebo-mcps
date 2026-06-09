import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { verifyCertificateBundle } from "../src/verify/certificate-verifier.js";
import { digestValue, signEd25519 } from "../src/strata/primitives.js";

const RECEIPT_VERSION = "turnstile.receipt.v1";
const GENESIS_ROOT = "0".repeat(64);

test("valid Managed Agent witness bundle verifies", async () => {
  const report = await verifyCertificateBundle(buildManagedAgentBundle());

  assert.equal(report.ok, true);
  assert.equal(report.summary.fail, 0);
  assert.equal(check(report, "managed_agent.bundle.version").ok, true);
  assert.equal(check(report, "managed_agent.receipt_chain.signatures").ok, true);
  assert.equal(check(report, "managed_agent.evidence.payload_digests").ok, true);
  assert.equal(check(report, "managed_agent.l2.denied_actions_not_executed").ok, true);
  assert.equal(check(report, "managed_agent.artifacts.generated_hashes").ok, true);
  assert.equal(report.evidence.managed_agent.agent_profile_id, "resident-engineer");
  assert.equal(report.evidence.managed_agent.policy_decision_count, 2);
});

test("Managed Agent verifier accepts local PoC API bundle envelopes", async () => {
  const report = await verifyCertificateBundle({ ok: true, bundle: buildManagedAgentBundle() });

  assert.equal(report.ok, true);
  assert.equal(check(report, "managed_agent.bundle.version").ok, true);
});

test("Managed Agent verifier fails when denied tool later executes", async () => {
  const report = await verifyCertificateBundle(buildManagedAgentBundle({ includeDeniedResult: true }));

  assert.equal(report.ok, false);
  assert.equal(check(report, "managed_agent.l2.denied_actions_not_executed").ok, false);
});

function buildManagedAgentBundle({ includeDeniedResult = false } = {}) {
  const sessionId = "sesn_managed_agent_verifier_test";
  const orgId = "amotivv-demo";
  const chainId = `org:${orgId}:session:${sessionId}`;
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" });
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" });
  const keyId = "gateway:amotivv-demo:test-managed-agent-verifier";
  const receipts = [];
  const evidence = [];

  const pushReceipt = ({ kind, direction = "inbound", eventType, eventId = null, eventKey, payload, typedSummary = {}, processedAt = null }) => {
    const stepIndex = receipts.length;
    const issuedAt = `2026-06-08T00:00:${String(stepIndex).padStart(2, "0")}.000Z`;
    const payloadDigest = digestValue(payload ?? null);
    const subject = {
      domain: "managed-agent.observed.v1",
      session_id: chainId,
      step_index: stepIndex,
      org_id: orgId,
      user_id: "demo",
      anthropic_session_id: sessionId,
      receipt_class: kind,
      source: {
        platform: "anthropic_managed_agents",
        direction,
        event_type: eventType,
        event_id: eventId,
        processed_at: processedAt,
      },
      payload_digest: payloadDigest,
      typed_summary: typedSummary,
      observed_at: issuedAt,
    };
    const base = {
      version: RECEIPT_VERSION,
      kind,
      session_id: chainId,
      step_index: stepIndex,
      prev_state_root: receipts.at(-1)?.state_root || GENESIS_ROOT,
      actor: { type: "gateway", id: "managed-agent-observer:amotivv-demo" },
      body: {
        assurance_mode: "observed-l1",
        workflow_id: "managed-agent.observed",
        profile_id: "profile.managed-agent.observed-l1.v1",
        event_key: eventKey,
        event_type: eventType,
        event_id: eventId,
        direction,
        payload_digest: payloadDigest,
        subject_digest: digestValue(subject),
        subject,
        typed_summary: typedSummary,
        witness_sign_request_digest: digestValue({ test: eventKey }),
        external_witness_signatures: [],
      },
      issued_at: issuedAt,
    };
    const signed = {
      ...base,
      signatures: [{ key_id: keyId, alg: "Ed25519", sig: signEd25519(receiptSigningMessage(base), privateKeyPem) }],
    };
    const receipt = { ...signed, state_root: stateRoot(signed) };
    receipts.push(receipt);
    evidence.push({ event_key: eventKey, payload_digest: payloadDigest, payload, observed_at: issuedAt });
  };

  pushReceipt({
    kind: "managed_agent.session.created",
    direction: "local-side-effect",
    eventType: "managed_agent.session.created",
    eventId: sessionId,
    eventKey: `session-created:${sessionId}`,
    payload: { session: { id: sessionId }, policy_mode: "governed", profile_id: "resident-engineer", skill_ids: [] },
    typedSummary: { policy_mode: "governed", profile_id: "resident-engineer", skill_ids: [], file_count: 0, github_repo_count: 0 },
  });

  const allowedTool = {
    id: "sevt_write_allowed",
    type: "agent.tool_use",
    name: "write",
    input: { file_path: "/mnt/session/outputs/smoke.txt", content: "SMOKE_OK\n" },
    processed_at: "2026-06-08T00:00:01.000Z",
  };
  pushToolRequest(pushReceipt, allowedTool);
  pushPolicy(pushReceipt, sessionId, allowedTool, { decision: "allow", matchedRules: ["allow-session-output-or-temp-write"] });
  pushReceipt({
    kind: "managed_agent.tool.result_observed",
    eventType: "agent.tool_result",
    eventId: "sevt_write_allowed_result",
    eventKey: "anthropic:sevt_write_allowed_result",
    processedAt: "2026-06-08T00:00:02.000Z",
    payload: { id: "sevt_write_allowed_result", type: "agent.tool_result", tool_use_id: allowedTool.id, is_error: false, content: [{ type: "text", text: "File created" }] },
    typedSummary: { event_type: "agent.tool_result", tool_use_id: allowedTool.id, is_error: false },
  });
  pushReceipt({
    kind: "managed_agent.file.generated",
    direction: "local-side-effect",
    eventType: "managed_agent.file.generated",
    eventId: "file_smoke",
    eventKey: `generated-file:${sessionId}:file_smoke:57d896726a213a627eb008a73e6ae3d685b21f7682800be46baaae75e43aeefb`,
    payload: {
      file: { id: "file_smoke", filename: "smoke.txt", mime_type: "text/plain", size_bytes: 9, downloadable: true, scope: { type: "session", id: sessionId } },
      content_sha256: "57d896726a213a627eb008a73e6ae3d685b21f7682800be46baaae75e43aeefb",
      downloaded_bytes: 9,
      content_type: "text/plain",
    },
    typedSummary: { file_id: "file_smoke", filename: "smoke.txt", mime_type: "text/plain", size_bytes: 9, downloadable: true, content_sha256: "57d896726a213a627eb008a73e6ae3d685b21f7682800be46baaae75e43aeefb" },
  });

  const deniedTool = {
    id: "sevt_write_denied",
    type: "agent.tool_use",
    name: "write",
    input: { file_path: "/workspace/release-note.md", content: "The workspace is ready for review.\n" },
    processed_at: "2026-06-08T00:00:03.000Z",
  };
  pushToolRequest(pushReceipt, deniedTool);
  pushPolicy(pushReceipt, sessionId, deniedTool, { decision: "deny", matchedRules: ["deny-write-path:/workspace/release-note.md"] });
  pushReceipt({
    kind: "managed_agent.tool.confirmed",
    direction: "outbound",
    eventType: "user.tool_confirmation",
    eventId: null,
    eventKey: "outbound:tool_confirmation:test:user.tool_confirmation:0",
    payload: { type: "user.tool_confirmation", tool_use_id: deniedTool.id, result: "deny", deny_message: "Attexa policy denied this action." },
    typedSummary: { event_type: "user.tool_confirmation", result: "deny", tool_use_id: deniedTool.id },
  });
  if (includeDeniedResult) {
    pushReceipt({
      kind: "managed_agent.tool.result_observed",
      eventType: "agent.tool_result",
      eventId: "sevt_write_denied_result",
      eventKey: "anthropic:sevt_write_denied_result",
      payload: { id: "sevt_write_denied_result", type: "agent.tool_result", tool_use_id: deniedTool.id, is_error: false, content: [{ type: "text", text: "File created" }] },
      typedSummary: { event_type: "agent.tool_result", tool_use_id: deniedTool.id, is_error: false },
    });
  }

  const bundleBody = {
    version: "attexa.managed_agent.witness_bundle.v1",
    manifest: {
      org_id: orgId,
      chain_id: chainId,
      anthropic_session_id: sessionId,
      workflow_id: "managed-agent.observed",
      profile_id: "profile.managed-agent.observed-l1.v1",
      assurance_mode: "observed-l1",
      created_at: "2026-06-08T00:00:00.000Z",
    },
    keyring: { [keyId]: publicKeyPem },
    receipts,
    evidence,
    verifier_profile: {
      version: "attexa.verifier_profile.v1",
      profile_id: "profile.managed-agent.observed-l1.v1",
      assurance_mode: "observed-l1",
      workflow_id: "managed-agent.observed",
      claim: "Externally observed Claude Managed Agents protocol events and artifact hashes are signed into a tamper-evident receipt chain.",
    },
    verification: { ok: true, errors: [], receipt_count: receipts.length, final_state_root: receipts.at(-1).state_root },
  };
  return { ...bundleBody, bundle_digest: digestValue(bundleBody) };
}

function pushToolRequest(pushReceipt, event) {
  pushReceipt({
    kind: "managed_agent.tool.requested",
    eventType: event.type,
    eventId: event.id,
    eventKey: `anthropic:${event.id}`,
    processedAt: event.processed_at,
    payload: event,
    typedSummary: { event_type: event.type, tool_name: event.name, input: { file_path: { sample: event.input.file_path } } },
  });
}

function pushPolicy(pushReceipt, sessionId, event, { decision, matchedRules }) {
  const policyBundleDigest = "ff969ee6a7e81df48133a592b9930e88de62db37e4091a7726215f6a12b3ebd0";
  const request = {
    version: "attexa.managed_agent.action_request.v1",
    session_id: sessionId,
    profile_id: "resident-engineer",
    policy_mode: "governed",
    event_id: event.id,
    event_type: event.type,
    tool_name: event.name,
    mcp_server_name: null,
    mcp_tool_name: event.name,
    session_thread_id: null,
    input: event.input,
  };
  const payload = {
    version: "attexa.managed_agent.policy_decision.v1",
    domain: "policy.managed_agent.tool",
    policy_id: "managed-agent-policy.v1",
    policy_epoch_id: "managed-agent-policy-epoch-001",
    policy_bundle_version: "attexa.managed_agent.policy_bundle.v1",
    policy_bundle_digest: policyBundleDigest,
    issued_at: "2026-06-08T00:00:04.000Z",
    session_id: sessionId,
    profile_id: "resident-engineer",
    event_id: event.id,
    event_type: event.type,
    tool_name: event.name,
    mcp_server_name: null,
    mcp_tool_name: event.name,
    decision,
    reason: decision === "deny" ? "Write target is reserved by policy: /workspace/release-note.md" : "File mutation target is under an allowed path prefix.",
    matched_rules: matchedRules,
    request_digest: digestValue(request),
    request,
    decision_source: "local",
  };
  pushReceipt({
    kind: "managed_agent.policy.evaluated",
    direction: "local-side-effect",
    eventType: "managed_agent.policy.evaluated",
    eventId: event.id,
    eventKey: `policy-evaluated:${sessionId}:${event.id}:${policyBundleDigest}`,
    payload,
    typedSummary: {
      policy_id: payload.policy_id,
      policy_epoch_id: payload.policy_epoch_id,
      policy_bundle_digest: payload.policy_bundle_digest,
      domain: payload.domain,
      decision: payload.decision,
      reason: payload.reason,
      decision_source: payload.decision_source,
      matched_rules: payload.matched_rules,
      request_digest: payload.request_digest,
      event_id: payload.event_id,
      tool_name: payload.tool_name,
      mcp_tool_name: payload.mcp_tool_name,
      profile_id: payload.profile_id,
    },
  });
}

function receiptSigningMessage(receipt) {
  return `${RECEIPT_VERSION}\n${digestValue(receiptPayload(receipt))}`;
}

function receiptPayload(receipt) {
  const { signatures: _signatures, state_root: _stateRoot, ...payload } = receipt;
  return payload;
}

function stateRoot(receipt) {
  return digestValue({
    protocol: "turnstile-state-root-v1",
    prev_state_root: receipt.prev_state_root,
    payload_digest: digestValue(receiptPayload(receipt)),
    signatures: receipt.signatures || [],
  });
}

function check(report, name) {
  const item = report.checks.find((entry) => entry.name === name);
  assert.ok(item, `Expected check ${name}`);
  return item;
}

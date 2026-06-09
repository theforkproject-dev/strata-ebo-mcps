import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { canonicalize, digestValue, signEd25519, verifyEd25519 } from "../strata/primitives.js";

export const MANAGED_AGENT_POLICY_BUNDLE_VERSION = "attexa.managed_agent.policy_bundle.v1";
export const MANAGED_AGENT_POLICY_DECISION_VERSION = "attexa.managed_agent.policy_decision.v1";
export const MANAGED_AGENT_POLICY_QUORUM_VERSION = "attexa.managed_agent.policy_quorum.v1";
export const MANAGED_AGENT_POLICY_DOMAIN = "policy.managed_agent.tool";
export const MANAGED_AGENT_POLICY_EPOCH_ID = "managed-agent-policy-epoch-001";
export const DEFAULT_MANAGED_AGENT_POLICY_FILE = "policies/managed-agent-policy-epoch-001.json";

export function defaultManagedAgentPolicyBundle() {
  return loadManagedAgentPolicyBundleSync();
}

export function loadManagedAgentPolicyBundleSync({ file } = {}) {
  const filePath = resolvePolicyFile(file);
  const policyBundle = JSON.parse(readFileSync(filePath, "utf8"));
  return validateManagedAgentPolicyBundle(policyBundle, filePath);
}

export async function loadManagedAgentPolicyBundle({ file, url, fetchImpl = fetch } = {}) {
  if (url) {
    const response = await fetchImpl(url);
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.error || `managed-agent policy bundle request returned ${response.status}`);
    }
    return validateManagedAgentPolicyBundle(policyBundleFromEnvelope(body), url);
  }
  return loadManagedAgentPolicyBundleSync({ file });
}

export function policyBundleFromEnvelope(body) {
  if (body?.version === MANAGED_AGENT_POLICY_BUNDLE_VERSION) return body;
  if (body?.policy_bundle?.version === MANAGED_AGENT_POLICY_BUNDLE_VERSION) return body.policy_bundle;
  throw new Error("response did not contain an attexa.managed_agent.policy_bundle.v1 policy bundle");
}

export function validateManagedAgentPolicyBundle(policyBundle, source = "policy bundle") {
  if (!policyBundle || typeof policyBundle !== "object" || Array.isArray(policyBundle)) {
    throw new Error(`${source} must be an object`);
  }
  if (policyBundle.version !== MANAGED_AGENT_POLICY_BUNDLE_VERSION) {
    throw new Error(`${source} has unsupported policy bundle version: ${policyBundle.version}`);
  }
  if (!policyBundle.policy_id || !policyBundle.epoch_id || !policyBundle.rules) {
    throw new Error(`${source} must include policy_id, epoch_id, and rules`);
  }
  return policyBundle;
}

export function managedAgentPolicyBundleDigest(policyBundle = defaultManagedAgentPolicyBundle()) {
  return digestValue(policyBundle);
}

export function evaluateManagedAgentPolicy({ request, policyBundle = defaultManagedAgentPolicyBundle() }) {
  const rules = policyBundle.rules || {};
  const toolName = request?.tool_name || "tool";
  const mcpToolName = request?.mcp_tool_name || toolName;
  const input = request?.input || {};
  const ruleResults = [];
  let decision = "requires_human";

  if (request?.event_type === "agent.tool_use" && (rules.allow_tools || []).includes(toolName)) {
    decision = "allow";
    ruleResults.push(rule(`allow-${toolName}`, true, { reason: `${toolName} is read-only inspection allowed by policy.` }));
  }

  if (toolName === "write" || toolName === "edit") {
    const target = String(input.file_path || input.path || "");
    const deniedPath = (rules.deny_write_paths || []).find((item) => target === item);
    if (deniedPath) {
      decision = "deny";
      ruleResults.push(rule(`deny-write-path:${deniedPath}`, false, { reason: rules.deny_write_reasons?.[deniedPath] || `Write target is reserved by policy: ${deniedPath}`, target }));
    } else {
      const allowed = (rules.allow_write_path_prefixes || []).some((prefix) => target.startsWith(prefix));
      if (allowed) {
        decision = "allow";
        ruleResults.push(rule("allow-session-output-or-temp-write", true, { target }));
      } else {
        decision = "requires_human";
        ruleResults.push(rule("review-write-outside-output-path", true, { target, reason: "File mutation outside approved output/temp paths requires human review." }));
      }
    }
  }

  if (toolName === "bash") {
    decision = "requires_human";
    ruleResults.push(rule("review-bash-command", true, { reason: "Bash commands require human review unless explicitly denied by policy." }));
    const command = String(input.command || input.cmd || input.bash_command || "");
    for (const pattern of rules.deny_bash_patterns || []) {
      const re = new RegExp(pattern, "i");
      if (re.test(command)) {
        decision = "deny";
        ruleResults.push(rule(`deny-bash:${pattern}`, false, { reason: rules.deny_bash_reasons?.[pattern] || `Bash command matched denied policy pattern: ${pattern}` }));
        break;
      }
    }
  }

  if ((rules.require_human_for_tools || []).includes(toolName) && decision !== "deny") {
    decision = "requires_human";
    ruleResults.push(rule(`review-tool:${toolName}`, true, { reason: `${toolName} requires human review by policy.` }));
  }

  if (request?.event_type === "agent.mcp_tool_use" && (rules.require_human_for_mcp_tools || []).includes(mcpToolName) && decision !== "deny") {
    decision = "requires_human";
    ruleResults.push(rule(`review-mcp-tool:${mcpToolName}`, true, { reason: `${mcpToolName} MCP action requires human review by policy.` }));
  }

  const failed = ruleResults.filter((item) => item.pass === false);
  return {
    version: MANAGED_AGENT_POLICY_DECISION_VERSION,
    policy_id: policyBundle.policy_id,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_digest: managedAgentPolicyBundleDigest(policyBundle),
    decision,
    reasons: failed.map((item) => item.rule),
    rule_results: ruleResults,
    request_digest: request ? digestValue(request) : null,
  };
}

export function createManagedAgentPolicyDecisionSubject({ witnessId, policyBundle, policyUrl = "", request, issuedAt = new Date().toISOString() }) {
  const evaluation = evaluateManagedAgentPolicy({ request, policyBundle });
  return {
    version: MANAGED_AGENT_POLICY_DECISION_VERSION,
    domain: request?.domain || MANAGED_AGENT_POLICY_DOMAIN,
    witness_id: witnessId,
    issued_at: issuedAt,
    policy_id: policyBundle.policy_id,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_digest: managedAgentPolicyBundleDigest(policyBundle),
    policy_url: policyUrl || null,
    session_id: request?.session_id || null,
    profile_id: request?.profile_id || null,
    event_id: request?.event_id || null,
    event_type: request?.event_type || null,
    tool_name: request?.tool_name || null,
    mcp_server_name: request?.mcp_server_name || null,
    mcp_tool_name: request?.mcp_tool_name || null,
    request_digest: evaluation.request_digest,
    input_digest: digestValue(request?.input || {}),
    decision: evaluation.decision,
    reasons: evaluation.reasons,
    rule_results: evaluation.rule_results
  };
}

export function signManagedAgentPolicyDecisionSubject(subject, signer) {
  return {
    key_id: signer.keyId,
    algorithm: "Ed25519",
    signature: signEd25519(canonicalize(subject), signer.privateKey)
  };
}

export function verifyManagedAgentPolicyDecisionSubject(subject, signature, publicKeyPem) {
  const ok = Boolean(signature?.signature && publicKeyPem && verifyEd25519(canonicalize(subject), signature.signature, publicKeyPem));
  return { ok, errors: ok ? [] : ["Managed Agent policy decision signature verification failed"] };
}

export async function collectManagedAgentPolicyQuorum({ witnesses, request, policyBundle = defaultManagedAgentPolicyBundle(), policyUrl = "", threshold = 2, fetchImpl = fetch }) {
  const expectedPolicyDigest = managedAgentPolicyBundleDigest(policyBundle);
  const expectedRequestDigest = digestValue(request);
  const decisions = [];
  const errors = [];

  for (const witness of witnesses) {
    const baseUrl = witness.url.replace(/\/$/, "");
    try {
      const publicKeyResponse = await fetchImpl(`${baseUrl}/v1/public-key`);
      const publicKey = await publicKeyResponse.json();
      if (!publicKeyResponse.ok) throw new Error(publicKey.error || `public key request returned ${publicKeyResponse.status}`);

      const response = await fetchImpl(`${baseUrl}/v1/evaluate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          domain: request.domain || MANAGED_AGENT_POLICY_DOMAIN,
          request,
          policy_epoch_id: policyBundle.epoch_id,
          policy_bundle_digest: expectedPolicyDigest,
          policy_url: policyUrl || null
        })
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || `policy witness returned ${response.status}`);

      const verification = verifyManagedAgentPolicyDecisionSubject(body.subject, body.signature, publicKey.public_key_pem);
      if (!verification.ok) throw new Error(verification.errors.join("; "));
      if (body.subject.version !== MANAGED_AGENT_POLICY_DECISION_VERSION) throw new Error(`unsupported Managed Agent policy decision version: ${body.subject.version}`);
      if (body.subject.policy_bundle_digest !== expectedPolicyDigest) throw new Error("policy bundle digest mismatch");
      if (body.subject.request_digest !== expectedRequestDigest) throw new Error("Managed Agent request digest mismatch");

      decisions.push({ witness_id: witness.id, url: witness.url, key_id: publicKey.key_id, subject: body.subject, signature: body.signature });
    } catch (error) {
      errors.push({ witness_id: witness.id, url: witness.url, error: error.message });
    }
  }

  const allowDecisions = decisions.filter((decision) => decision.subject.decision === "allow");
  const denyDecisions = decisions.filter((decision) => decision.subject.decision === "deny");
  const reviewDecisions = decisions.filter((decision) => decision.subject.decision === "requires_human");
  const quorumDecision = denyDecisions.length >= threshold ? "deny" : allowDecisions.length >= threshold ? "allow" : reviewDecisions.length >= threshold ? "requires_human" : "deny";
  return {
    version: MANAGED_AGENT_POLICY_QUORUM_VERSION,
    ok: ["allow", "requires_human"].includes(quorumDecision),
    threshold,
    policy_id: policyBundle.policy_id,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_digest: expectedPolicyDigest,
    policy_url: policyUrl || null,
    request_digest: expectedRequestDigest,
    decision: quorumDecision,
    allow_count: allowDecisions.length,
    deny_count: denyDecisions.length,
    requires_human_count: reviewDecisions.length,
    total_witnesses: witnesses.length,
    deny_reasons: [...new Set(denyDecisions.flatMap((decision) => decision.subject.reasons || []))],
    decisions,
    errors
  };
}

function resolvePolicyFile(file) {
  if (file && existsSync(file)) return file;
  if (file) return resolve(process.cwd(), file);
  return new URL(`../../${DEFAULT_MANAGED_AGENT_POLICY_FILE}`, import.meta.url);
}

function rule(name, pass, details = {}) {
  return { rule: name, pass: Boolean(pass), details };
}

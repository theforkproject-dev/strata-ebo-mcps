import { canonicalize, digestValue, signEd25519, verifyEd25519 } from "../strata/primitives.js";
import { KOJIMEM_POLICY_DECISION_VERSION, KOJIMEM_WORKFLOW_ID } from "../kojimem/canonical.js";

export const KOJIMEM_POLICY_BUNDLE_VERSION = "strata.kojimem.policy_bundle.v1";
export const KOJIMEM_POLICY_QUORUM_VERSION = "strata.kojimem.policy_quorum.v1";
export const KOJIMEM_POLICY_DOMAIN = "policy.kojimem.agent_handoff";

export function defaultKojimemPolicyBundle(config) {
  return {
    version: KOJIMEM_POLICY_BUNDLE_VERSION,
    policy_id: "kojimem-agent-handoff-policy.v1",
    epoch_id: "kojimem-agent-handoff-policy-epoch-001",
    workflow_id: KOJIMEM_WORKFLOW_ID,
    rules: {
      max_ttl: config.kojimem.maxTtl,
      allowed_data_classes: ["issuer_fraud_signals"],
      allowed_delegation_actions: ["recall", "destroy"],
      allowed_recall_tiers: ["fast", "balanced", "reasoning"],
      require_specific_delegate_wallet: true,
      disallow_open_delegation: true,
      require_destroy_after_recall: true,
      l3_required_above_exposure_usd: config.kojimem.l3ExposureThresholdUsd,
      require_l3_claim_type: "fraud-data-release",
      require_l3_decision: "approve"
    }
  };
}

export function kojimemPolicyBundleDigest(policyBundle) {
  return digestValue(policyBundle);
}

export function evaluateKojimemPolicy({ request, input = {}, config, policyBundle = defaultKojimemPolicyBundle(config) }) {
  const rules = policyBundle.rules;
  const ruleResults = [];
  const delegationActions = request?.delegation?.actions || [];
  const disallowedActions = delegationActions.filter((action) => !rules.allowed_delegation_actions.includes(action));
  const requestDigest = request ? digestValue(request) : null;
  const attestation = input.l3_attestation || null;
  const exposureUsd = Number(request?.risk?.estimated_exposure_usd || 0);
  const thresholdUsd = Number(rules.l3_required_above_exposure_usd || 0);
  const l3Required = exposureUsd > thresholdUsd;

  ruleResults.push(rule("ttl_within_limit", ttlSeconds(request?.backpack?.ttl) <= ttlSeconds(rules.max_ttl), {
    actual: request?.backpack?.ttl || null,
    maximum: rules.max_ttl
  }));
  ruleResults.push(rule("data_class_allowed", rules.allowed_data_classes.includes(request?.backpack?.data_class), {
    actual: request?.backpack?.data_class || null,
    allowed: rules.allowed_data_classes
  }));
  ruleResults.push(rule("specific_delegate_wallet", !rules.require_specific_delegate_wallet || Boolean(request?.delegation?.delegate_wallet), {
    delegate_wallet_present: Boolean(request?.delegation?.delegate_wallet)
  }));
  ruleResults.push(rule("open_delegation_disallowed", !rules.disallow_open_delegation || !request?.delegation?.open_delegation, {
    open_delegation: Boolean(request?.delegation?.open_delegation)
  }));
  ruleResults.push(rule("delegation_scope_allowed", disallowedActions.length === 0 && delegationActions.length > 0, {
    actual: delegationActions,
    disallowed: disallowedActions,
    allowed: rules.allowed_delegation_actions
  }));
  ruleResults.push(rule("recall_tier_allowed", rules.allowed_recall_tiers.includes(request?.recall?.tier), {
    actual: request?.recall?.tier || null,
    allowed: rules.allowed_recall_tiers
  }));
  ruleResults.push(rule("destroy_after_recall_required", Boolean(rules.require_destroy_after_recall) && delegationActions.includes("destroy"), {
    destroy_in_scope: delegationActions.includes("destroy")
  }));
  ruleResults.push(rule("l3_threshold_evaluated", true, {
    estimated_exposure_usd: exposureUsd,
    threshold_usd: thresholdUsd,
    requires_l3: l3Required
  }));
  if (l3Required) {
    ruleResults.push(rule("l3_attestation_present", Boolean(attestation), {
      required_claim_type: rules.require_l3_claim_type
    }));
    ruleResults.push(rule("l3_claim_type_matches", attestation?.claim_type === rules.require_l3_claim_type, {
      actual: attestation?.claim_type || null,
      required: rules.require_l3_claim_type
    }));
    ruleResults.push(rule("l3_decision_approved", attestation?.decision === rules.require_l3_decision, {
      actual: attestation?.decision || null,
      required: rules.require_l3_decision
    }));
    ruleResults.push(rule("l3_binds_request_digest", attestation?.request_digest === requestDigest, {
      actual: attestation?.request_digest || null,
      expected: requestDigest
    }));
  }

  const failed = ruleResults.filter((item) => !item.pass);
  return {
    version: KOJIMEM_POLICY_DECISION_VERSION,
    policy_id: policyBundle.policy_id,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_digest: kojimemPolicyBundleDigest(policyBundle),
    decision: failed.length === 0 ? "allow" : "deny",
    reasons: failed.map((item) => item.rule),
    rule_results: ruleResults,
    request_digest: requestDigest,
    l3_required: l3Required ? {
      claim_type: rules.require_l3_claim_type,
      reason: `Estimated fraud exposure $${exposureUsd.toLocaleString()} exceeds the L3 threshold of $${thresholdUsd.toLocaleString()}.`
    } : null
  };
}

export function createKojimemPolicyDecisionSubject({ witnessId, policyBundle, policyUrl = "", request, input, config, issuedAt = new Date().toISOString() }) {
  const evaluation = evaluateKojimemPolicy({ request, input, config, policyBundle });
  return {
    version: KOJIMEM_POLICY_DECISION_VERSION,
    domain: KOJIMEM_POLICY_DOMAIN,
    witness_id: witnessId,
    issued_at: issuedAt,
    policy_id: policyBundle.policy_id,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_digest: kojimemPolicyBundleDigest(policyBundle),
    policy_url: policyUrl || null,
    workflow_id: KOJIMEM_WORKFLOW_ID,
    request_digest: evaluation.request_digest,
    input_digest: digestValue(input || {}),
    decision: evaluation.decision,
    reasons: evaluation.reasons,
    rule_results: evaluation.rule_results,
    l3_required: evaluation.l3_required
  };
}

export function signKojimemPolicyDecisionSubject(subject, signer) {
  return {
    key_id: signer.keyId,
    algorithm: "Ed25519",
    signature: signEd25519(canonicalize(subject), signer.privateKey)
  };
}

export function verifyKojimemPolicyDecisionSubject(subject, signature, publicKeyPem) {
  const ok = Boolean(signature?.signature && publicKeyPem && verifyEd25519(canonicalize(subject), signature.signature, publicKeyPem));
  return {
    ok,
    errors: ok ? [] : ["Kojimem policy decision signature verification failed"]
  };
}

export async function collectKojimemPolicyQuorum({ witnesses, request, input, config, policyBundle = defaultKojimemPolicyBundle(config), policyUrl = "", threshold = 2, fetchImpl = fetch }) {
  const expectedPolicyDigest = kojimemPolicyBundleDigest(policyBundle);
  const expectedRequestDigest = digestValue(request);
  const decisions = [];
  const errors = [];

  for (const witness of witnesses) {
    const baseUrl = witness.url.replace(/\/$/, "");
    try {
      const publicKeyResponse = await fetchImpl(`${baseUrl}/v1/public-key`);
      const publicKey = await publicKeyResponse.json();
      if (!publicKeyResponse.ok) {
        throw new Error(publicKey.error || `public key request returned ${publicKeyResponse.status}`);
      }

      const response = await fetchImpl(`${baseUrl}/v1/evaluate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          domain: KOJIMEM_POLICY_DOMAIN,
          workflow_id: KOJIMEM_WORKFLOW_ID,
          input,
          request,
          policy_epoch_id: policyBundle.epoch_id,
          policy_bundle_digest: expectedPolicyDigest,
          policy_url: policyUrl || null
        })
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.error || `policy witness returned ${response.status}`);
      }

      const verification = verifyKojimemPolicyDecisionSubject(body.subject, body.signature, publicKey.public_key_pem);
      if (!verification.ok) {
        throw new Error(verification.errors.join("; "));
      }
      if (body.subject.version !== KOJIMEM_POLICY_DECISION_VERSION) {
        throw new Error(`unsupported Kojimem policy decision version: ${body.subject.version}`);
      }
      if (body.subject.policy_bundle_digest !== expectedPolicyDigest) {
        throw new Error("policy bundle digest mismatch");
      }
      if (body.subject.request_digest !== expectedRequestDigest) {
        throw new Error("Kojimem request digest mismatch");
      }

      decisions.push({
        witness_id: witness.id,
        url: witness.url,
        key_id: publicKey.key_id,
        subject: body.subject,
        signature: body.signature
      });
    } catch (error) {
      errors.push({ witness_id: witness.id, url: witness.url, error: error.message });
    }
  }

  const allowDecisions = decisions.filter((decision) => decision.subject.decision === "allow");
  const denyDecisions = decisions.filter((decision) => decision.subject.decision === "deny");
  const denyReasons = [...new Set(denyDecisions.flatMap((decision) => decision.subject.reasons || []))];
  return {
    version: KOJIMEM_POLICY_QUORUM_VERSION,
    ok: allowDecisions.length >= threshold,
    threshold,
    policy_id: policyBundle.policy_id,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_digest: expectedPolicyDigest,
    policy_url: policyUrl || null,
    request_digest: expectedRequestDigest,
    decision: allowDecisions.length >= threshold ? "allow" : "deny",
    allow_count: allowDecisions.length,
    deny_count: denyDecisions.length,
    total_witnesses: witnesses.length,
    deny_reasons: denyReasons,
    decisions,
    errors
  };
}

function ttlSeconds(value) {
  const match = String(value || "").match(/^(\d+)([hm])$/);
  if (!match) return Number.POSITIVE_INFINITY;
  const amount = Number(match[1]);
  return match[2] === "h" ? amount * 3600 : amount * 60;
}

function rule(name, pass, details = {}) {
  return { rule: name, pass: Boolean(pass), details };
}

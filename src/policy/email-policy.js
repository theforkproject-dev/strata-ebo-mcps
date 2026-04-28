import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize, digestValue, signEd25519, verifyEd25519 } from "../strata/primitives.js";

export const EMAIL_POLICY_BUNDLE_VERSION = "strata.email.policy_bundle.v1";
export const EMAIL_POLICY_DECISION_VERSION = "strata.email.policy_decision.v1";
export const EMAIL_POLICY_POINTER_VERSION = "strata.email.policy_pointer.v1";
export const DEFAULT_EMAIL_POLICY_EPOCH_ID = "email-policy-epoch-001";
export const DEFAULT_EMAIL_POLICY_FILE = "policies/email-policy-epoch-001.json";

const DEFAULT_POLICY_FILE_URL = new URL("../../policies/email-policy-epoch-001.json", import.meta.url);

export function defaultEmailPolicyBundle() {
  return loadEmailPolicyBundleSync();
}

export function loadEmailPolicyBundleSync({ file } = {}) {
  const filePath = resolvePolicyFile(file);
  const policyBundle = JSON.parse(readFileSync(filePath, "utf8"));
  return validateEmailPolicyBundle(policyBundle, filePath);
}

export async function loadEmailPolicyBundle({ file, url, fetchImpl = fetch } = {}) {
  if (url) {
    const response = await fetchImpl(url);
    const body = await response.json();
    if (!response.ok) {
      throw new Error(body.error || `policy bundle request returned ${response.status}`);
    }
    return validateEmailPolicyBundle(policyBundleFromEnvelope(body), url);
  }
  return loadEmailPolicyBundleSync({ file });
}

export function policyBundleFromEnvelope(body) {
  if (body?.version === EMAIL_POLICY_BUNDLE_VERSION) {
    return body;
  }
  if (body?.policy_bundle?.version === EMAIL_POLICY_BUNDLE_VERSION) {
    return body.policy_bundle;
  }
  throw new Error("response did not contain a strata.email.policy_bundle.v1 policy bundle");
}

export function validateEmailPolicyBundle(policyBundle, source = "policy bundle") {
  if (!policyBundle || typeof policyBundle !== "object" || Array.isArray(policyBundle)) {
    throw new Error(`${source} must be an object`);
  }
  if (policyBundle.version !== EMAIL_POLICY_BUNDLE_VERSION) {
    throw new Error(`${source} has unsupported policy bundle version: ${policyBundle.version}`);
  }
  if (!policyBundle.policy_id || !policyBundle.epoch_id || !policyBundle.rules) {
    throw new Error(`${source} must include policy_id, epoch_id, and rules`);
  }
  return policyBundle;
}

export function policyBundleMetadata(policyBundle, policyUrl = "") {
  return {
    policy_id: policyBundle.policy_id,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_version: policyBundle.version,
    policy_bundle_digest: policyBundleDigest(policyBundle),
    policy_url: policyUrl || null
  };
}

export function policyBundleDigest(policyBundle = defaultEmailPolicyBundle()) {
  return digestValue(policyBundle);
}

export function evaluateEmailPolicy({ email, commitment, policyBundle = defaultEmailPolicyBundle() }) {
  const rules = policyBundle.rules;
  const recipients = [...(email.to || []), ...(email.cc || []), ...(email.bcc || [])];
  const recipientDomains = recipients.map(domainOf).filter(Boolean);
  const content = [email.subject, email.text, email.html].filter(Boolean).join("\n").toLowerCase();
  const tags = email.tags || {};
  const ruleResults = [];

  ruleResults.push(ruleResult("from_domain_allowed", rules.allowed_from_domains.includes(domainOf(email.from)), {
    actual: domainOf(email.from),
    allowed: rules.allowed_from_domains
  }));
  ruleResults.push(ruleResult("recipient_domains_allowed", recipientDomains.every((domain) => rules.allowed_recipient_domains.includes(domain)), {
    actual: recipientDomains,
    allowed: rules.allowed_recipient_domains
  }));
  ruleResults.push(ruleResult("max_recipients", recipients.length <= rules.max_recipients, {
    actual: recipients.length,
    maximum: rules.max_recipients
  }));
  ruleResults.push(ruleResult("subject_prefix", String(email.subject || "").startsWith(rules.require_subject_prefix), {
    required_prefix: rules.require_subject_prefix
  }));
  const deniedKeywords = rules.deny_keywords.filter((keyword) => content.includes(keyword.toLowerCase()));
  ruleResults.push(ruleResult("deny_keywords_absent", deniedKeywords.length === 0, {
    denied_keywords_found: deniedKeywords
  }));
  const missingTags = rules.require_tags.filter((tag) => !Object.prototype.hasOwnProperty.call(tags, tag) || !String(tags[tag]).trim());
  ruleResults.push(ruleResult("required_tags_present", missingTags.length === 0, {
    missing_tags: missingTags,
    required_tags: rules.require_tags
  }));

  const failed = ruleResults.filter((result) => !result.pass);
  return {
    decision: failed.length === 0 ? "allow" : "deny",
    reasons: failed.map((result) => result.rule),
    rule_results: ruleResults,
    policy_bundle_digest: policyBundleDigest(policyBundle),
    policy_epoch_id: policyBundle.epoch_id,
    email_payload_digest: commitment.payload_digest,
    commitment_schema_version: commitment.version
  };
}

export function createPolicyDecisionSubject({ witnessId, policyBundle, policyUrl = "", email, commitment, issuedAt = new Date().toISOString() }) {
  const evaluation = evaluateEmailPolicy({ email, commitment, policyBundle });
  return {
    version: EMAIL_POLICY_DECISION_VERSION,
    domain: "policy.email.send",
    witness_id: witnessId,
    issued_at: issuedAt,
    policy_id: policyBundle.policy_id,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_digest: policyBundleDigest(policyBundle),
    policy_url: policyUrl || null,
    email_payload_digest: commitment.payload_digest,
    commitment_schema_version: commitment.version,
    decision: evaluation.decision,
    reasons: evaluation.reasons,
    rule_results: evaluation.rule_results
  };
}

export function signPolicyDecisionSubject(subject, signer) {
  return {
    key_id: signer.keyId,
    algorithm: "Ed25519",
    signature: signEd25519(canonicalize(subject), signer.privateKey)
  };
}

export function verifyPolicyDecisionSubject(subject, signature, publicKeyPem) {
  const ok = Boolean(signature?.signature && publicKeyPem && verifyEd25519(canonicalize(subject), signature.signature, publicKeyPem));
  return {
    ok,
    errors: ok ? [] : ["policy decision signature verification failed"]
  };
}

export function verifyPolicyQuorumAuthority({ policyQuorum, registryEpoch, workflowId, policyHash, requiredTier = "policy" }) {
  const errors = [];
  const checks = [];
  const registryByKey = new Map((registryEpoch?.witnesses || []).map((witness) => [witness.key_id, witness]));
  const requiredRank = tierRank(requiredTier);

  for (const decision of policyQuorum?.decisions || []) {
    const keyId = decision.signature?.key_id || decision.key_id;
    const witness = registryByKey.get(keyId);
    const decisionErrors = [];

    if (!witness) {
      decisionErrors.push(`policy witness key ${keyId} is not in registry epoch ${registryEpoch?.epoch_id}`);
    } else {
      if (witness.witness_id !== decision.witness_id) {
        decisionErrors.push(`witness_id mismatch for ${keyId}: decision=${decision.witness_id} registry=${witness.witness_id}`);
      }
      if (!isAuthorizedForWorkflow(witness, workflowId)) {
        decisionErrors.push(`${keyId} is not authorized for workflow ${workflowId}`);
      }
      if (!isAuthorizedForPolicy(witness, policyHash)) {
        decisionErrors.push(`${keyId} is not authorized for policy ${policyHash}`);
      }
      if (tierRank(witness.tier) < requiredRank) {
        decisionErrors.push(`${keyId} tier ${witness.tier} is below required tier ${requiredTier}`);
      }
      decisionErrors.push(...authorizationTimeErrors(witness, decision.subject?.issued_at));
      const signature = verifyPolicyDecisionSubject(decision.subject, decision.signature, witness.public_key_pem);
      decisionErrors.push(...signature.errors);
    }

    checks.push({
      witness_id: decision.witness_id,
      key_id: keyId,
      decision: decision.subject?.decision,
      signing_time: decision.subject?.issued_at,
      ok: decisionErrors.length === 0,
      errors: decisionErrors
    });
    errors.push(...decisionErrors);
  }

  const authorizedCount = checks.filter((check) => check.ok).length;
  if (authorizedCount < (policyQuorum?.threshold || 1)) {
    errors.push(`policy quorum authorized threshold not met: ${authorizedCount}/${policyQuorum?.threshold || 1}`);
  }

  return {
    ok: errors.length === 0,
    errors,
    workflow_id: workflowId,
    policy_hash: policyHash,
    required_tier: requiredTier,
    authorized_policy_witness_keys: checks.filter((check) => check.ok).map((check) => check.key_id),
    checks
  };
}

export async function collectPolicyQuorum({ witnesses, email, commitment, policyBundle = defaultEmailPolicyBundle(), policyUrl = "", threshold = 2, fetchImpl = fetch }) {
  const expectedPolicyDigest = policyBundleDigest(policyBundle);
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
          email,
          commitment,
          policy_epoch_id: policyBundle.epoch_id,
          policy_bundle_digest: expectedPolicyDigest,
          policy_url: policyUrl || null
        })
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.error || `policy witness returned ${response.status}`);
      }

      const verification = verifyPolicyDecisionSubject(body.subject, body.signature, publicKey.public_key_pem);
      if (!verification.ok) {
        throw new Error(verification.errors.join("; "));
      }
      if (body.subject.policy_bundle_digest !== expectedPolicyDigest) {
        throw new Error("policy bundle digest mismatch");
      }
      if (body.subject.email_payload_digest !== commitment.payload_digest) {
        throw new Error("email payload digest mismatch");
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
  const denyReasons = [...new Set(denyDecisions.flatMap((decision) => decision.subject.reasons))];
  return {
    version: "strata.email.policy_quorum.v1",
    ok: allowDecisions.length >= threshold,
    threshold,
    policy_id: policyBundle.policy_id,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_digest: expectedPolicyDigest,
    policy_url: policyUrl || null,
    decision: allowDecisions.length >= threshold ? "allow" : "deny",
    allow_count: allowDecisions.length,
    deny_count: denyDecisions.length,
    total_witnesses: witnesses.length,
    deny_reasons: denyReasons,
    decisions,
    errors
  };
}

function resolvePolicyFile(file) {
  if (!file) {
    return fileURLToPath(DEFAULT_POLICY_FILE_URL);
  }
  if (file.startsWith("file://")) {
    return fileURLToPath(file);
  }
  const candidate = resolve(file);
  if (existsSync(candidate)) {
    return candidate;
  }
  return resolve(process.cwd(), file);
}

function ruleResult(rule, pass, details = {}) {
  return { rule, pass, details };
}

function domainOf(address) {
  const value = String(address || "").trim();
  const match = value.match(/<([^<>]+)>$/);
  const mailbox = match ? match[1] : value;
  const at = mailbox.lastIndexOf("@");
  return at === -1 ? null : mailbox.slice(at + 1).toLowerCase();
}

const TIER_RANK = { mechanical: 1, policy: 2, domain: 3 };

function tierRank(tier) {
  return TIER_RANK[tier] || 0;
}

function isAuthorizedForWorkflow(witness, workflowId) {
  return (witness.authorized_workflows || []).includes(workflowId);
}

function isAuthorizedForPolicy(witness, policyHash) {
  return (witness.authorized_policy_hashes || []).includes(policyHash);
}

function authorizationTimeErrors(witness, signingTime) {
  const errors = [];
  if (!signingTime || Number.isNaN(Date.parse(signingTime))) {
    return [`invalid signing time for ${witness.key_id}: ${signingTime}`];
  }
  const signedAt = new Date(signingTime).getTime();
  if (witness.valid_from && signedAt < new Date(witness.valid_from).getTime()) {
    errors.push(`${witness.key_id} was not valid until ${witness.valid_from}`);
  }
  if (witness.valid_until && signedAt >= new Date(witness.valid_until).getTime()) {
    errors.push(`${witness.key_id} authorization expired at ${witness.valid_until}`);
  }
  if ((witness.status || "active") !== "active") {
    errors.push(`${witness.key_id} status is ${witness.status}`);
  }
  return errors;
}

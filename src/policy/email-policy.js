import { canonicalize, digestValue, sha256Hex, signEd25519, verifyEd25519 } from "../strata/primitives.js";

export const EMAIL_POLICY_BUNDLE_VERSION = "strata.email.policy_bundle.v1";
export const EMAIL_POLICY_DECISION_VERSION = "strata.email.policy_decision.v1";

export function defaultEmailPolicyBundle() {
  return {
    version: EMAIL_POLICY_BUNDLE_VERSION,
    policy_id: "email-policy.v1",
    epoch_id: "email-policy-epoch-001",
    rules: {
      allowed_from_domains: ["theforkproject.com"],
      allowed_recipient_domains: ["amotivv.com"],
      max_recipients: 3,
      require_subject_prefix: "[Verified]",
      deny_keywords: ["password", "secret key", "wire transfer"],
      require_tags: ["conversation_id", "turn_id"],
      allowed_tools: ["email_send_verified"]
    }
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

export function createPolicyDecisionSubject({ witnessId, policyBundle, email, commitment, issuedAt = new Date().toISOString() }) {
  const evaluation = evaluateEmailPolicy({ email, commitment, policyBundle });
  return {
    version: EMAIL_POLICY_DECISION_VERSION,
    domain: "policy.email.send",
    witness_id: witnessId,
    issued_at: issuedAt,
    policy_id: policyBundle.policy_id,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_digest: policyBundleDigest(policyBundle),
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

export async function collectPolicyQuorum({ witnesses, email, commitment, threshold = 2, fetchImpl = fetch }) {
  const policyBundle = defaultEmailPolicyBundle();
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
        body: JSON.stringify({ email, commitment, policy_bundle_digest: expectedPolicyDigest })
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
    decision: allowDecisions.length >= threshold ? "allow" : "deny",
    allow_count: allowDecisions.length,
    deny_count: denyDecisions.length,
    total_witnesses: witnesses.length,
    deny_reasons: denyReasons,
    decisions,
    errors
  };
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

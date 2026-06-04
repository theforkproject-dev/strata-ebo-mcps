import { canonicalize, digestValue, signEd25519, verifyEd25519 } from "../strata/primitives.js";
import { SUPABASE_POLICY_DECISION_VERSION, classifyReadOnlySql } from "../supabase/canonical.js";

export const SUPABASE_POLICY_BUNDLE_VERSION = "strata.supabase.policy_bundle.v1";
export const SUPABASE_POLICY_QUORUM_VERSION = "strata.supabase.policy_quorum.v1";

export function defaultSupabasePolicyBundle(config) {
  return {
    version: SUPABASE_POLICY_BUNDLE_VERSION,
    policy_id: "supabase-policy.v1",
    epoch_id: "supabase-policy-epoch-001",
    rules: {
      require_project_ref: true,
      require_read_only: true,
      allowed_features: ["database", "docs"],
      allowed_tools: [
        "supabase_list_tables_verified",
        "supabase_inspect_schema_verified",
        "supabase_query_readonly_verified",
        "supabase_search_docs"
      ],
      max_rows: config.supabase.maxRows,
      timeout_ms: config.supabase.timeoutMs,
      blocked_schemas: config.supabase.blockedSchemas,
      blocked_tables: config.supabase.blockedTables
    }
  };
}

export function supabasePolicyBundleDigest(policyBundle) {
  return digestValue(policyBundle);
}

export function evaluateSupabasePolicy({ toolName, input, request, config, policyBundle = defaultSupabasePolicyBundle(config) }) {
  const rules = policyBundle.rules;
  const effectiveSupabase = {
    ...config.supabase,
    projectRef: request?.project_ref || config.supabase.projectRef,
    readOnly: request?.read_only ?? config.supabase.readOnly,
    features: request?.features || config.supabase.features,
    maxRows: rules.max_rows,
    timeoutMs: rules.timeout_ms,
    blockedSchemas: rules.blocked_schemas || [],
    blockedTables: rules.blocked_tables || []
  };
  const effectiveConfig = { ...config, supabase: effectiveSupabase };
  const ruleResults = [];
  ruleResults.push(rule("project_ref_configured", !rules.require_project_ref || Boolean(effectiveSupabase.projectRef), { project_ref_present: Boolean(effectiveSupabase.projectRef) }));
  ruleResults.push(rule("read_only_required", !rules.require_read_only || Boolean(effectiveSupabase.readOnly), { read_only: effectiveSupabase.readOnly }));
  const normalizedToolName = normalizeSupabaseToolName(toolName);
  ruleResults.push(rule("tool_allowed", rules.allowed_tools.includes(normalizedToolName), { tool_name: toolName, normalized_tool_name: normalizedToolName, allowed_tools: rules.allowed_tools }));
  const featureErrors = effectiveSupabase.features.filter((feature) => !rules.allowed_features.includes(feature));
  ruleResults.push(rule("features_allowed", featureErrors.length === 0, { configured_features: effectiveSupabase.features, disallowed_features: featureErrors }));

  let sqlClassification = null;
  if (normalizeSupabaseToolName(toolName) === "supabase_query_readonly_verified" || normalizeSupabaseToolName(toolName) === "supabase_inspect_schema_verified") {
    sqlClassification = classifyReadOnlySql(request?.upstream_arguments?.query || input?.query || "", effectiveConfig);
    ruleResults.push(rule("sql_read_only", sqlClassification.ok, { errors: sqlClassification.errors, sql_digest: sqlClassification.sql_digest }));
  }

  const failed = ruleResults.filter((item) => !item.pass);
  return {
    version: SUPABASE_POLICY_DECISION_VERSION,
    policy_id: policyBundle.policy_id,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_digest: supabasePolicyBundleDigest(policyBundle),
    decision: failed.length === 0 ? "allow" : "deny",
    reasons: failed.map((item) => item.rule),
    rule_results: ruleResults,
    request_digest: request ? digestValue(request) : null,
    sql: sqlClassification
  };
}

export function createSupabasePolicyDecisionSubject({ witnessId, policyBundle, policyUrl = "", toolName, input, request, config, issuedAt = new Date().toISOString() }) {
  const evaluation = evaluateSupabasePolicy({ toolName, input, request, config, policyBundle });
  return {
    version: SUPABASE_POLICY_DECISION_VERSION,
    domain: "policy.supabase.mcp",
    witness_id: witnessId,
    issued_at: issuedAt,
    policy_id: policyBundle.policy_id,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_digest: supabasePolicyBundleDigest(policyBundle),
    policy_url: policyUrl || null,
    tool_name: normalizeSupabaseToolName(toolName),
    request_digest: request ? digestValue(request) : null,
    input_digest: digestValue(input || {}),
    sql_digest: evaluation.sql?.sql_digest || null,
    decision: evaluation.decision,
    reasons: evaluation.reasons,
    rule_results: evaluation.rule_results
  };
}

export function signSupabasePolicyDecisionSubject(subject, signer) {
  return {
    key_id: signer.keyId,
    algorithm: "Ed25519",
    signature: signEd25519(canonicalize(subject), signer.privateKey)
  };
}

export function verifySupabasePolicyDecisionSubject(subject, signature, publicKeyPem) {
  const ok = Boolean(signature?.signature && publicKeyPem && verifyEd25519(canonicalize(subject), signature.signature, publicKeyPem));
  return {
    ok,
    errors: ok ? [] : ["Supabase policy decision signature verification failed"]
  };
}

export async function collectSupabasePolicyQuorum({ witnesses, toolName, input, request, config, policyBundle = defaultSupabasePolicyBundle(config), policyUrl = "", threshold = 2, fetchImpl = fetch }) {
  const expectedPolicyDigest = supabasePolicyBundleDigest(policyBundle);
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
          domain: "policy.supabase.mcp",
          tool_name: normalizeSupabaseToolName(toolName),
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

      const verification = verifySupabasePolicyDecisionSubject(body.subject, body.signature, publicKey.public_key_pem);
      if (!verification.ok) {
        throw new Error(verification.errors.join("; "));
      }
      if (body.subject.version !== SUPABASE_POLICY_DECISION_VERSION) {
        throw new Error(`unsupported Supabase policy decision version: ${body.subject.version}`);
      }
      if (body.subject.policy_bundle_digest !== expectedPolicyDigest) {
        throw new Error("policy bundle digest mismatch");
      }
      if (body.subject.request_digest !== expectedRequestDigest) {
        throw new Error("Supabase request digest mismatch");
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
    version: SUPABASE_POLICY_QUORUM_VERSION,
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

function normalizeSupabaseToolName(toolName) {
  return String(toolName || "")
    .replace(/^supabase\./, "supabase_")
    .replace(/^nango_supabase_/, "supabase_");
}

function rule(name, pass, details = {}) {
  return { rule: name, pass: Boolean(pass), details };
}

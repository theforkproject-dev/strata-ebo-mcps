import { digestValue } from "../strata/primitives.js";
import { SUPABASE_POLICY_DECISION_VERSION, classifyReadOnlySql } from "../supabase/canonical.js";

export const SUPABASE_POLICY_BUNDLE_VERSION = "strata.supabase.policy_bundle.v1";

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
        "supabase.list_tables_verified",
        "supabase.inspect_schema_verified",
        "supabase.query_readonly_verified",
        "supabase.search_docs"
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
  const ruleResults = [];
  ruleResults.push(rule("project_ref_configured", !rules.require_project_ref || Boolean(config.supabase.projectRef), { project_ref_present: Boolean(config.supabase.projectRef) }));
  ruleResults.push(rule("read_only_required", !rules.require_read_only || Boolean(config.supabase.readOnly), { read_only: config.supabase.readOnly }));
  ruleResults.push(rule("tool_allowed", rules.allowed_tools.includes(toolName), { tool_name: toolName, allowed_tools: rules.allowed_tools }));
  const featureErrors = config.supabase.features.filter((feature) => !rules.allowed_features.includes(feature));
  ruleResults.push(rule("features_allowed", featureErrors.length === 0, { configured_features: config.supabase.features, disallowed_features: featureErrors }));

  let sqlClassification = null;
  if (toolName === "supabase.query_readonly_verified" || toolName === "supabase.inspect_schema_verified") {
    sqlClassification = classifyReadOnlySql(request?.upstream_arguments?.query || input?.query || "", config);
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

function rule(name, pass, details = {}) {
  return { rule: name, pass: Boolean(pass), details };
}

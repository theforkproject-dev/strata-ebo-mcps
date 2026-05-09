import assert from "node:assert/strict";
import test from "node:test";
import { verifyCertificateBundle } from "../src/verify/certificate-verifier.js";
import { digestValue } from "../src/strata/primitives.js";

test("valid Supabase action bundle verifies under phase-1 profile", async () => {
  const report = await verifyCertificateBundle(buildSupabaseBundle());

  assert.equal(report.ok, true);
  assert.equal(report.summary.fail, 0);
  assert.equal(check(report, "bundle.version").ok, true);
  assert.equal(check(report, "supabase.connector_manifest.digest").ok, true);
  assert.equal(check(report, "supabase.request.digest").ok, true);
  assert.equal(check(report, "supabase.result_metadata.digest_only").ok, true);
  assert.equal(check(report, "supabase.receipt_parity.pending").severity, "warn");
});

test("Supabase verifier fails when connector manifest digest is tampered", async () => {
  const bundle = buildSupabaseBundle();
  bundle.connector_manifest.upstream.project_ref = "different-project";

  const report = await verifyCertificateBundle(bundle);

  assert.equal(report.ok, false);
  assert.equal(check(report, "supabase.connector_manifest.digest").ok, false);
  assert.equal(check(report, "supabase.connector_binding.project_scope").ok, false);
});

test("Supabase verifier fails when request artifact is tampered", async () => {
  const bundle = buildSupabaseBundle();
  bundle.supabase_request.input.query = "select * from public.accounts";

  const report = await verifyCertificateBundle(bundle);

  assert.equal(report.ok, false);
  assert.equal(check(report, "supabase.request.digest").ok, false);
  assert.equal(check(report, "supabase.request.input_digest").ok, false);
});

test("Supabase verifier rejects raw result payloads in durable metadata", async () => {
  const bundle = buildSupabaseBundle();
  bundle.supabase_result_metadata.text = "raw Supabase row payload";

  const report = await verifyCertificateBundle(bundle);

  assert.equal(report.ok, false);
  assert.equal(check(report, "supabase.result_metadata.digest_only").ok, false);
  assert.equal(check(report, "supabase.raw_live_payload_absent").ok, false);
});

test("valid Supabase policy-denial bundle verifies under phase-1 profile", async () => {
  const report = await verifyCertificateBundle(buildSupabaseBundle({ denied: true }));

  assert.equal(report.ok, true);
  assert.equal(report.summary.fail, 0);
  assert.equal(check(report, "certificate.version").ok, true);
  assert.equal(check(report, "supabase.denied_consistency").ok, true);
  assert.equal(check(report, "supabase.proof.side_effect").ok, true);
});

function buildSupabaseBundle({ denied = false } = {}) {
  const connectorManifest = {
    version: "strata.supabase.connector_manifest.v1",
    connector_id: "heyjil-supabase-pilot",
    connector_label: "HeyJil Supabase Pilot",
    connector_type: "supabase_mcp",
    upstream: {
      origin: "https://mcp.supabase.com",
      base_url: "https://mcp.supabase.com/mcp",
      project_ref: "ghmfczkhbwfftvpsrghy",
      read_only: true,
      features: ["database", "docs"]
    },
    evidence_mode: "digest-only",
    constraints: {
      max_rows: 100,
      timeout_ms: 30000,
      blocked_schemas: ["auth", "storage", "vault"],
      blocked_tables: []
    },
    tools: [
      tool("supabase_list_tables_verified", "list_tables"),
      tool("supabase_inspect_schema_verified", "execute_sql"),
      tool("supabase_query_readonly_verified", "execute_sql"),
      tool("supabase_search_docs", "search_docs")
    ]
  };
  const request = {
    version: "strata.supabase.request.v1",
    connector_id: "heyjil-supabase-pilot",
    project_ref: "ghmfczkhbwfftvpsrghy",
    read_only: true,
    features: ["database", "docs"],
    strata_tool_name: "supabase_query_readonly_verified",
    upstream_tool_name: "execute_sql",
    upstream_arguments: { query: "select * from public.chat_sessions limit 100" },
    input: { query: "select * from public.chat_sessions" }
  };
  const policyBundle = {
    version: "strata.supabase.policy_bundle.v1",
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
      max_rows: 100,
      timeout_ms: 30000,
      blocked_schemas: ["auth", "storage", "vault"],
      blocked_tables: []
    }
  };
  const sql = {
    ok: !denied,
    normalized_sql: "select * from public.chat_sessions limit 100",
    sql_digest: digestValue({ sql: "select * from public.chat_sessions limit 100" }),
    first_token: "select",
    statement_count: 1,
    errors: denied ? ["schema is blocked by connector policy: auth"] : []
  };
  const policyDecision = {
    version: "strata.supabase.policy_decision.v1",
    policy_id: policyBundle.policy_id,
    policy_epoch_id: policyBundle.epoch_id,
    policy_bundle_digest: digestValue(policyBundle),
    decision: denied ? "deny" : "allow",
    reasons: denied ? ["sql_read_only"] : [],
    rule_results: denied ? [{ rule: "sql_read_only", pass: false, details: { errors: sql.errors, sql_digest: sql.sql_digest } }] : [{ rule: "sql_read_only", pass: true, details: { errors: [], sql_digest: sql.sql_digest } }],
    request_digest: digestValue(request),
    sql
  };
  const resultMetadata = denied ? { upstream_error: null } : {
    version: "strata.supabase.result_summary.v1",
    result_digest: digestValue({ result: [{ id: 1 }] }),
    result_text_digest: digestValue({ text: JSON.stringify({ result: [{ id: 1 }] }) }),
    result_bytes: Buffer.byteLength(JSON.stringify({ result: [{ id: 1 }] }), "utf8"),
    row_count: 1,
    evidence_mode: "digest-only"
  };
  const verification = {
    ok: !denied,
    phase: "supabase-mcp-governance-proxy-v0.1",
    policy: { ok: !denied, decision: policyDecision.decision, reasons: policyDecision.reasons },
    upstream: { ok: !denied, error: null, error_category: null }
  };
  const certificateBody = {
    version: denied ? "strata.supabase.policy_denial_certificate.v1" : "strata.supabase.mcp_action_certificate.v1",
    run_id: "supabase_test_run",
    certificate_url: "https://gateway.example.test/certificates/supabase_test_run",
    bundle_url: "https://gateway.example.test/certificates/supabase_test_run/bundle",
    issued_at: "2026-05-09T17:00:00.000Z",
    denied,
    action: {
      mcp_tool_name: request.strata_tool_name,
      upstream_tool_name: request.upstream_tool_name,
      method: "MCP tools/call"
    },
    connector: {
      connector_id: connectorManifest.connector_id,
      connector_label: connectorManifest.connector_label,
      connector_type: connectorManifest.connector_type,
      auth_mode: "supabase_manual_oauth_app",
      credential_fingerprint: "sha256:test-fingerprint",
      project_ref: request.project_ref,
      read_only: true,
      features: request.features,
      upstream_origin: connectorManifest.upstream.origin,
      upstream_url: "https://mcp.supabase.com/mcp?project_ref=ghmfczkhbwfftvpsrghy&read_only=true&features=database%2Cdocs",
      connector_manifest_digest: digestValue(connectorManifest)
    },
    request: {
      request_digest: digestValue(request),
      sql_digest: policyDecision.sql.sql_digest,
      input_digest: digestValue(request.input)
    },
    policy: {
      tier: "level-2-policy-scaffold",
      decision: policyDecision.decision,
      reasons: policyDecision.reasons,
      policy_id: policyDecision.policy_id,
      policy_epoch_id: policyDecision.policy_epoch_id,
      policy_bundle_version: policyBundle.version,
      policy_bundle_digest: policyDecision.policy_bundle_digest,
      rule_results: policyDecision.rule_results
    },
    proof: {
      assurance_mode: "mcp-governance-proxy-phase1-scaffold",
      witness_tiers: ["level-1-mechanical", "level-2-policy"],
      mechanical_witness_quorum: "2-of-3",
      policy_witness_quorum: "2-of-3",
      side_effect_executed: !denied,
      verified: !denied,
      note: "Phase-1 scaffold records connector policy and upstream result digests."
    },
    result: denied ? null : resultMetadata,
    result_preview: null,
    session: {
      tenant_id: "default",
      operator_id: "operator:amotivv-demo",
      assistant_id: "claude-desktop-test"
    },
    artifacts: {},
    errors: []
  };
  const certificate = { ...certificateBody, certificate_digest: digestValue(certificateBody) };
  return {
    version: "strata.supabase.certificate_bundle.v1",
    run_id: certificate.run_id,
    bundle_url: certificate.bundle_url,
    gateway_bundle_url: certificate.bundle_url,
    durable_publication: {
      backend: "s3-cloudfront",
      scope: "complete_bundle_only",
      bundle_url: "https://durable.example.test/certificates/supabase/supabase_test_run/bundle.json",
      no_overwrite: true,
      retention_mode: "GOVERNANCE"
    },
    certificate,
    receipts: [],
    keyring: null,
    checkpoint: null,
    transparency_log: [],
    verification,
    admission_manifest: null,
    operator_registry: null,
    policy_decision: policyDecision,
    policy_bundle: policyBundle,
    registry_epoch: null,
    gateway_attestation: null,
    l1_witness_attestations: null,
    connector_manifest: connectorManifest,
    supabase_request: request,
    supabase_result_metadata: resultMetadata,
    recipient_verifications: []
  };
}

function check(report, name) {
  return report.checks.find((item) => item.name === name) || assert.fail(`missing check: ${name}`);
}

function tool(strataTool, upstreamTool) {
  return {
    strata_tool: strataTool,
    upstream_tool: upstreamTool,
    policy_class: "database.read",
    canonicalizer: "supabase.query.v1",
    certificate_profile: "supabase.query.v1",
    human_approval_required: false
  };
}

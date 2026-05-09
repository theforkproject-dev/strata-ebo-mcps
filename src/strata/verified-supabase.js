import { randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { digestValue } from "./primitives.js";
import { loadCertificateBundle } from "../certificates/bundle.js";
import { publishCertificateBundle } from "../certificates/publisher.js";
import { evaluateSupabasePolicy, defaultSupabasePolicyBundle } from "../policy/supabase-policy.js";
import {
  SUPABASE_ACTION_CERTIFICATE_VERSION,
  SUPABASE_ACTION_REGISTRY_VERSION,
  canonicalSupabaseRequest,
  classifyReadOnlySql,
  connectorManifest,
  connectorManifestDigest,
  credentialFingerprint,
  enforceLimit,
  redactSupabaseResult,
  summarizeSupabaseResult,
  supabaseToolResultPayload,
  upstreamMcpUrl,
  upstreamOrigin
} from "../supabase/canonical.js";
import { SupabaseMcpClient, loadSupabaseConnectorCredential } from "../supabase/upstream-mcp-client.js";

export async function createSupabaseActionRegistry(config) {
  const manifest = connectorManifest(config);
  const policyBundle = defaultSupabasePolicyBundle(config);
  return {
    version: SUPABASE_ACTION_REGISTRY_VERSION,
    registry_id: "action-registry.supabase-mcp",
    epoch_id: "supabase-mcp-epoch-v1",
    connector_manifest_digest: connectorManifestDigest(config),
    protocol: supabaseProtocolVersions(),
    tools: supabaseTools(config),
    actions: manifest.tools.map((tool) => ({
      action_id: tool.strata_tool,
      mcp_tool_name: tool.strata_tool,
      upstream_tool_name: tool.upstream_tool,
      assurance: {
        mode: "witnessed-readonly-phase1",
        required_witness_tiers: ["mechanical", "policy"],
        mechanical_quorum: { threshold: config.witness.threshold, set: "witness-set.supabase-mcp.l1" },
        policy_quorum: { threshold: config.policyWitness.threshold, set: "witness-set.supabase-mcp.l2-policy" }
      },
      policy: {
        policy_bundle_hash: digestValue(policyBundle),
        policy_bundle_version: policyBundle.version,
        policy_epoch_id: policyBundle.epoch_id,
        policy_summary: policyBundle.rules
      },
      adapter: {
        adapter_id: "supabase-hosted-mcp",
        implementation: "Strata Supabase MCP governance proxy",
        upstream_origin: upstreamOrigin(config)
      },
      persisted_payload_policy: config.supabase.evidenceMode
    }))
  };
}

export async function supabaseGatewayStatus(config) {
  const credential = await loadSupabaseConnectorCredential(config);
  const policyBundle = defaultSupabasePolicyBundle(config);
  const missing = [];
  if (!config.supabase.projectRef) missing.push("SUPABASE_PROJECT_REF");
  if (!config.supabase.readOnly) missing.push("SUPABASE_MCP_READ_ONLY=true");
  if (!config.supabase.features.includes("database")) missing.push("SUPABASE_MCP_FEATURES must include database");
  if (!credential.access_token) missing.push("Supabase connector access token");
  return {
    status: missing.length === 0 ? "ready" : "setup_required",
    checked_at: new Date().toISOString(),
    protocol: supabaseProtocolVersions(),
    connector: publicConnectorBinding(config, credential),
    upstream: {
      url: upstreamMcpUrl(config),
      calls_enabled: config.supabase.upstreamCallsEnabled,
      note: config.supabase.upstreamCallsEnabled ? null : "SUPABASE_ENABLE_UPSTREAM_CALLS is false; tools will stop before calling Supabase MCP."
    },
    policy: {
      policy_id: policyBundle.policy_id,
      policy_epoch_id: policyBundle.epoch_id,
      policy_bundle_version: policyBundle.version,
      policy_bundle_digest: digestValue(policyBundle),
      rules: policyBundle.rules
    },
    assurance: {
      mode: "mcp-governance-proxy",
      witness_tiers: ["level-1-mechanical", "level-2-policy"],
      mechanical_witness_quorum_required: `${config.witness.threshold}-of-${config.witnesses.length}`,
      policy_witness_quorum_required: `${config.policyWitness.threshold}-of-${config.policyWitnesses.length}`,
      phase1_note: "Supabase scaffold enforces local read-only policy now; live L1/L2 witness wiring follows the email gateway pattern."
    },
    missing
  };
}

export async function runVerifiedSupabaseAction({ toolName, input, config, requestContext = {} }) {
  const runId = `supabase_${Date.now()}_${randomUUID().slice(0, 8)}`;
  const outDir = join(config.dataDir, "runs", runId);
  const certificateUrl = `${config.certificateBaseUrl}/${runId}`;
  mkdirSync(outDir, { recursive: true });

  const mapping = buildUpstreamCall(toolName, input, config);
  const request = canonicalSupabaseRequest({
    strataToolName: toolName,
    upstreamToolName: mapping.upstreamToolName,
    upstreamArguments: mapping.upstreamArguments,
    input,
    config
  });
  const policyBundle = defaultSupabasePolicyBundle(config);
  const policyDecision = evaluateSupabasePolicy({ toolName, input, request, config, policyBundle });
  writeJson(join(outDir, "connector-manifest.json"), connectorManifest(config));
  writeJson(join(outDir, "policy-bundle.json"), policyBundle);
  writeJson(join(outDir, "policy-decision.json"), policyDecision);
  writeJson(join(outDir, "supabase-request.json"), request);

  if (policyDecision.decision !== "allow") {
    return writeSupabaseCertificate({
      config,
      runId,
      outDir,
      certificateUrl,
      requestContext,
      request,
      policyBundle,
      policyDecision,
      upstreamResult: null,
      upstreamError: null,
      denied: true
    });
  }

  if (!config.supabase.upstreamCallsEnabled) {
    return writeSupabaseCertificate({
      config,
      runId,
      outDir,
      certificateUrl,
      requestContext,
      request,
      policyBundle,
      policyDecision,
      upstreamResult: null,
      upstreamError: "SUPABASE_ENABLE_UPSTREAM_CALLS is false",
      denied: false
    });
  }

  let upstreamResult = null;
  let upstreamError = null;
  try {
    const client = new SupabaseMcpClient(config);
    upstreamResult = await client.callTool(mapping.upstreamToolName, mapping.upstreamArguments);
  } catch (error) {
    upstreamError = error.message;
  }

  return writeSupabaseCertificate({
    config,
    runId,
    outDir,
    certificateUrl,
    requestContext,
    request,
    policyBundle,
    policyDecision,
    upstreamResult,
    upstreamError,
    denied: false
  });
}

function supabaseProtocolVersions() {
  return {
    certificate_schema_version: SUPABASE_ACTION_CERTIFICATE_VERSION,
    connector_manifest_schema_version: "strata.supabase.connector_manifest.v1",
    request_schema_version: "strata.supabase.request.v1",
    policy_bundle_schema_version: "strata.supabase.policy_bundle.v1",
    policy_decision_schema_version: "strata.supabase.policy_decision.v1"
  };
}

function supabaseTools(config) {
  return [
    {
      name: "gateway_status",
      title: "Check Strata Supabase Gateway Status",
      description: "Check Supabase connector configuration, project scoping, read-only mode, feature groups, and OAuth credential readiness.",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      annotations: { title: "Gateway status", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
    },
    {
      name: "supabase_list_tables_verified",
      title: "List Supabase Tables With Strata Evidence",
      description: "List tables from the configured Supabase project through the Strata governance proxy. Phase 1 is project-scoped and read-only.",
      inputSchema: {
        type: "object",
        properties: {
          schemas: { type: "array", items: { type: "string" }, default: ["public"] },
          verbose: { type: "boolean", default: false }
        },
        additionalProperties: false
      },
      annotations: { title: "Verified table list", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
    },
    {
      name: "supabase_inspect_schema_verified",
      title: "Inspect Supabase Schema With Strata Evidence",
      description: "Inspect schema metadata for the configured Supabase project using a constrained catalog query.",
      inputSchema: {
        type: "object",
        properties: {
          schema: { type: "string", default: "public" },
          table: { type: "string", description: "Optional table name to filter on." }
        },
        additionalProperties: false
      },
      annotations: { title: "Verified schema inspect", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
    },
    {
      name: "supabase_query_readonly_verified",
      title: "Run Read-Only Supabase Query With Strata Evidence",
      description: `Run a single read-only SQL query against the configured Supabase project. The gateway allows SELECT, WITH, or EXPLAIN only and enforces a max row policy of ${config.supabase.maxRows}.`,
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Single read-only SQL statement." }
        },
        required: ["query"],
        additionalProperties: false
      },
      annotations: { title: "Verified read-only query", readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true }
    },
    {
      name: "supabase_search_docs",
      title: "Search Supabase Docs",
      description: "Search Supabase documentation through the configured Supabase MCP server. Included because docs are part of the approved phase-1 feature set.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Convenience alias for graphql_query." },
          graphql_query: { type: "string", description: "GraphQL query string accepted by Supabase's upstream search_docs tool." }
        },
        anyOf: [
          { required: ["query"] },
          { required: ["graphql_query"] }
        ],
        additionalProperties: false
      },
      annotations: { title: "Search Supabase docs", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
    }
  ];
}

function buildUpstreamCall(toolName, input, config) {
  if (toolName === "supabase_list_tables_verified") {
    return {
      upstreamToolName: "list_tables",
      upstreamArguments: {
        schemas: input.schemas || ["public"],
        verbose: Boolean(input.verbose)
      }
    };
  }
  if (toolName === "supabase_inspect_schema_verified") {
    const query = schemaInspectQuery(input);
    return {
      upstreamToolName: "execute_sql",
      upstreamArguments: { query }
    };
  }
  if (toolName === "supabase_query_readonly_verified") {
    const classification = classifyReadOnlySql(input.query, config);
    return {
      upstreamToolName: "execute_sql",
      upstreamArguments: { query: classification.ok ? enforceLimit(input.query, config.supabase.maxRows) : input.query }
    };
  }
  if (toolName === "supabase_search_docs") {
    return {
      upstreamToolName: "search_docs",
      upstreamArguments: { graphql_query: input.graphql_query || input.query }
    };
  }
  throw new Error(`Unknown Supabase tool: ${toolName}`);
}

function schemaInspectQuery(input) {
  const schema = sqlLiteral(input.schema || "public");
  const tableClause = input.table ? `and table_name = ${sqlLiteral(input.table)}` : "";
  return `select table_schema, table_name, column_name, data_type, is_nullable, column_default from information_schema.columns where table_schema = ${schema} ${tableClause} order by table_schema, table_name, ordinal_position limit 500`;
}

async function writeSupabaseCertificate({ config, runId, outDir, certificateUrl, requestContext, request, policyBundle, policyDecision, upstreamResult, upstreamError, denied }) {
  const credential = await loadSupabaseConnectorCredential(config);
  const resultSummary = upstreamResult ? summarizeSupabaseResult(upstreamResult) : null;
  const toolResultPayload = supabaseToolResultPayload(upstreamResult, {
    mode: config.supabase.toolResultMode,
    maxChars: config.supabase.toolResultMaxChars
  });
  const verification = {
    ok: !denied && !upstreamError,
    phase: "supabase-mcp-governance-proxy-v0.1",
    policy: { ok: policyDecision.decision === "allow", decision: policyDecision.decision, reasons: policyDecision.reasons },
    upstream: { ok: Boolean(upstreamResult) && !upstreamError, error: upstreamError }
  };
  writeJson(join(outDir, "supabase-result-metadata.json"), resultSummary || { upstream_error: upstreamError || null });
  writeJson(join(outDir, "verification.json"), verification);

  const certificateBody = {
    version: denied ? "strata.supabase.policy_denial_certificate.v1" : SUPABASE_ACTION_CERTIFICATE_VERSION,
    run_id: runId,
    certificate_url: certificateUrl,
    bundle_url: `${certificateUrl}/bundle`,
    issued_at: new Date().toISOString(),
    denied,
    action: {
      mcp_tool_name: request.strata_tool_name,
      upstream_tool_name: request.upstream_tool_name,
      method: "MCP tools/call"
    },
    connector: publicConnectorBinding(config, credential),
    request: {
      request_digest: digestValue(request),
      sql_digest: policyDecision.sql?.sql_digest || null,
      input_digest: digestValue(request.input || {})
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
      mechanical_witness_quorum: `${config.witness.threshold}-of-${config.witnesses.length}`,
      policy_witness_quorum: `${config.policyWitness.threshold}-of-${config.policyWitnesses.length}`,
      side_effect_executed: Boolean(upstreamResult) && !denied,
      verified: verification.ok,
      note: "Phase-1 scaffold records connector policy and upstream result digests. Full L1/L2 receipt wiring will follow the email gateway ActionGateway path."
    },
    result: resultSummary,
    result_preview: config.supabase.evidenceMode === "redacted-sample" && upstreamResult ? redactSupabaseResult(upstreamResult) : null,
    session: {
      tenant_id: config.tenant.id,
      operator_id: config.operator.id,
      assistant_id: requestContext.session?.aid || requestContext.session?.client_id || null
    },
    artifacts: publicArtifactUrls(config, runId),
    errors: [upstreamError].filter(Boolean)
  };
  const certificateDigest = digestValue(certificateBody);
  const certificate = { ...certificateBody, certificate_digest: certificateDigest };
  writeJson(join(outDir, "certificate.json"), certificate);

  const bundle = loadCertificateBundle({ config, runId, runDir: outDir });
  const durablePublication = await publishCertificateBundle(config, { runId, certificateDigest, bundle });
  const durableBundleUrl = durablePublication?.status === "published" ? durablePublication.bundle_url : null;
  return {
    ok: verification.ok,
    denied,
    status: denied ? "policy_denied" : (verification.ok ? "completed" : "not_completed"),
    run_id: runId,
    certificate_ref: certificateUrl,
    certificate_url: certificateUrl,
    bundle_url: durableBundleUrl || `${certificateUrl}/bundle`,
    gateway_bundle_url: `${certificateUrl}/bundle`,
    durable_bundle_url: durableBundleUrl,
    durable_publication: durablePublication,
    certificate_digest: certificateDigest,
    connector: certificate.connector,
    policy: certificate.policy,
    result: resultSummary,
    tool_result: toolResultPayload,
    result_preview: certificate.result_preview,
    upstream_error: upstreamError,
    errors: certificate.errors
  };
}

function publicConnectorBinding(config, credential = {}) {
  return {
    connector_id: config.supabase.connectorId,
    connector_label: config.supabase.connectorLabel,
    connector_type: "supabase_mcp",
    auth_mode: "supabase_manual_oauth_app",
    credential_fingerprint: credentialFingerprint(config, credential),
    project_ref: config.supabase.projectRef || null,
    read_only: config.supabase.readOnly,
    features: config.supabase.features,
    upstream_origin: upstreamOrigin(config),
    upstream_url: upstreamMcpUrl(config),
    connector_manifest_digest: connectorManifestDigest(config)
  };
}

function publicArtifactUrls(config, runId) {
  const base = `${config.certificateBaseUrl}/${runId}/artifacts`;
  return {
    certificate: `${config.certificateBaseUrl}/${runId}`,
    bundle: `${config.certificateBaseUrl}/${runId}/bundle`,
    connector_manifest: `${base}/connector-manifest.json`,
    policy_bundle: `${base}/policy-bundle.json`,
    policy_decision: `${base}/policy-decision.json`,
    supabase_request: `${base}/supabase-request.json`,
    supabase_result_metadata: `${base}/supabase-result-metadata.json`,
    verification: `${base}/verification.json`
  };
}

function sqlLiteral(value) {
  return `'${String(value || "").replace(/'/g, "''")}'`;
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

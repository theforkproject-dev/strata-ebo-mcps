import { randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  ActionGateway,
  HttpWitnessClient,
  JsonlReceiptLog,
  LocalTransparencyLog,
  createAdmissionManifest,
  createTinfoilEvidence,
  createVerifierProfile,
  digestValue,
  loadOrCreateEd25519Signer,
  sha256Hex,
  toolRequestDigest,
  verifyCheckpoint,
  verifySession,
  verifyWitnessAuthority,
  writeCheckpoint
} from "./primitives.js";
import { loadCertificateBundle } from "../certificates/bundle.js";
import { createDurableBundleLocation, publishCertificateBundle } from "../certificates/publisher.js";
import { collectSupabasePolicyQuorum, defaultSupabasePolicyBundle, supabasePolicyBundleDigest } from "../policy/supabase-policy.js";
import {
  attachOperatorSignature,
  loadOperatorAdmissionSigner,
  operatorAdmissionCertificateBinding,
  verifyOperatorAdmissionManifest
} from "../admission/operator-manifest.js";
import { verifyPolicyQuorumAuthority } from "../policy/email-policy.js";
import { fetchOperatorRegistryBinding, fetchRegistryBinding } from "../registry/email-registry.js";
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
import { createSupabaseTool } from "../supabase/tool.js";
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
    client_hints: supabaseClientHints(config),
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
  if (config.witnesses.length < config.witness.threshold) {
    throw new Error(`Supabase verified actions require at least ${config.witness.threshold} Level 1 witness URL(s) in WITNESS_URLS`);
  }
  if (config.policyWitnesses.length < config.policyWitness.threshold) {
    throw new Error(`Supabase verified actions require at least ${config.policyWitness.threshold} Level 2 policy witness URL(s) in POLICY_WITNESS_URLS`);
  }

  const runId = `supabase_${Date.now()}_${randomUUID().slice(0, 8)}`;
  const outDir = join(config.dataDir, "runs", runId);
  const certificateUrl = `${config.certificateBaseUrl}/${runId}`;
  mkdirSync(outDir, { recursive: true });
  const paths = artifactPaths(outDir);

  const mapping = buildUpstreamCall(toolName, input, config);
  const request = canonicalSupabaseRequest({
    strataToolName: toolName,
    upstreamToolName: mapping.upstreamToolName,
    upstreamArguments: mapping.upstreamArguments,
    input,
    config
  });
  request.certificate_url = certificateUrl;
  const policyBundle = defaultSupabasePolicyBundle(config);
  const policyDecision = await collectSupabasePolicyQuorum({
    witnesses: config.policyWitnesses,
    toolName,
    input,
    request,
    config,
    policyBundle,
    threshold: config.policyWitness.threshold
  });
  writeJson(paths.connectorManifest, connectorManifest(config));
  writeJson(paths.policyBundle, policyBundle);
  writeJson(paths.policyDecision, policyDecision);
  writeJson(paths.supabaseRequest, request);

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

  const keys = loadGatewayKeys(config);
  const keyring = {
    [keys.gateway.signer.keyId]: keys.gateway.publicKeyPem,
    [keys.tool.signer.keyId]: keys.tool.publicKeyPem,
    [keys.transparency.signer.keyId]: keys.transparency.publicKeyPem
  };
  const witnesses = await createWitnessClients(config.witnesses, keyring, config, keys.gateway.signer);
  writeJson(paths.keyring, keyring);

  const policyHash = policyDecision.policy_bundle_digest;
  const registryBinding = await loadAndWriteRegistryBinding(config, paths.registryEpoch);
  const registryPreflight = registryBinding
    ? verifyConfiguredL1WitnessSetAuthority({ witnesses, registryBinding, policyHash: policyDecision.policy_bundle_digest, threshold: config.witness.threshold })
    : { ok: true, errors: [] };
  if (!registryPreflight.ok) {
    writeJson(paths.verification, { ok: false, registry_preflight: registryPreflight });
    throw new Error(`Supabase L1 registry preflight failed before upstream execution: ${registryPreflight.errors.join("; ")}`);
  }

  const log = new JsonlReceiptLog(paths.receipts);
  log.reset();
  const transparencyLog = new LocalTransparencyLog({
    filePath: paths.transparencyLog,
    signer: keys.transparency.signer,
    logId: "supabase-mcp-transparency-log"
  });
  transparencyLog.reset();

  const verifierProfile = createVerifierProfile({ profile_id: "profile.supabase-mcp.l1-l2.v1" });
  const admissionManifest = createSignedSupabaseAdmissionManifest({ config, requestContext, policyBundle, policyHash, egressPolicy: createEgressPolicy(config) });
  writeJson(paths.admissionManifest, admissionManifest);
  const operatorRegistryBinding = await loadAndWriteOperatorRegistryBinding(config, paths.operatorRegistry, admissionManifest);
  const client = new SupabaseMcpClient(config);
  const tool = createSupabaseTool({ signer: keys.tool.signer, gatewayKeyring: keyring, client });
  const gateway = new ActionGateway({
    log,
    signer: keys.gateway.signer,
    tools: { [tool.name]: tool },
    policyHash,
    verifierProfile,
    admissionManifest,
    witnesses,
    sideEffectWitnessThreshold: config.witness.threshold,
    sessionBoundaryWitnessThreshold: config.witness.threshold,
    checkpointWitnessThreshold: config.witness.threshold,
    transparencyLog
  });

  await gateway.startSession({ sessionId: `sess_${runId}`, taskInputDigest: digestValue(request) });
  const toolResult = await gateway.toolCall({
    toolName: "supabase-mcp",
    method: "MCP tools/call",
    request,
    inputEdges: [policyQuorumInput(policyDecision)]
  });
  await gateway.endSession(toolResult.output.upstream_error ? "upstream_error" : "complete");
  const checkpoint = await gateway.createCheckpoint({ checkpointId: `chk_${runId}` });
  writeCheckpoint(paths.checkpoint, checkpoint);

  const receipts = log.readAll();
  const transparencyLogEntries = transparencyLog.readAll();
  const session = verifySession(receipts, keyring, {
    transparencyLogEntries,
    requireAdmissionManifest: true,
    requireSideEffectQuorum: true,
    requireBoundaryQuorum: true,
    requireTransparencyLog: true
  });
  const checkpointResult = verifyCheckpoint(checkpoint, receipts, keyring, {
    transparencyLogEntries,
    requireCheckpointQuorum: true,
    requireCheckpointTransparency: true
  });
  const policyBundleVerification = verifyPolicyBundleForQuorum(policyBundle, policyDecision);
  const operatorAdmission = verifyOperatorAdmissionManifest(admissionManifest, {
    operatorRegistryBinding,
    requireRegistry: Boolean(config.registry?.url)
  });
  const registryAuthority = registryBinding ? verifyRegistryAuthority({ receipts, checkpoint, keyring, policyQuorum: policyDecision, registryBinding }) : null;
  const verified = session.ok && checkpointResult.ok && policyBundleVerification.ok && operatorAdmission.ok && (!registryAuthority || registryAuthority.ok) && !toolResult.output.upstream_error;
  const verification = { ok: verified, session, checkpoint: checkpointResult, policy_bundle: policyBundleVerification, operator_admission: operatorAdmission, operator_registry: operatorRegistryBinding?.verification || null, registry_authority: registryAuthority };
  writeJson(paths.verification, verification);

  return writeSupabaseCertificate({
    config,
    runId,
    outDir,
    certificateUrl,
    requestContext,
    request,
    policyBundle,
    policyDecision,
    upstreamResult: toolResult.output.upstream_result_live,
    upstreamError: toolResult.output.upstream_error,
    denied: false,
    witnessed: {
      receipts,
      checkpoint,
      session,
      checkpointResult,
      policyBundleVerification,
      operatorAdmission,
      admissionManifest,
      operatorRegistryBinding,
      registryBinding,
      registryAuthority,
      verified
    }
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
      description: "List tables from the configured Supabase project through the Strata governance proxy. This preserves the upstream Supabase MCP list_tables tool mapping; pass schemas such as ['public'] and optional verbose=true for more metadata. Phase 1 is project-scoped and read-only.",
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
      description: "Inspect schema metadata for the configured Supabase project using a gateway-generated read-only catalog query. Use schema/table filters when you need column-level detail before constructing a read-only SQL query.",
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
      description: `Run a single read-only SQL query against the configured Supabase project. Use the input field named query; it carries SQL text. The gateway allows SELECT, WITH, or EXPLAIN only and enforces a max row policy of ${config.supabase.maxRows}.`,
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
      description: "Search Supabase documentation through the configured Supabase MCP server. Supabase's upstream tool expects graphql_query; the Strata wrapper also accepts query as a convenience alias.",
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

async function writeSupabaseCertificate({ config, runId, outDir, certificateUrl, requestContext, request, policyBundle, policyDecision, upstreamResult, upstreamError, denied, witnessed = null }) {
  const credential = await loadSupabaseConnectorCredential(config);
  const resultSummary = upstreamResult ? summarizeSupabaseResult(upstreamResult) : null;
  const toolResultPayload = supabaseToolResultPayload(upstreamResult, {
    mode: config.supabase.toolResultMode,
    maxChars: config.supabase.toolResultMaxChars
  });
  const verification = {
    ok: witnessed ? witnessed.verified : (!denied && !upstreamError),
    phase: "supabase-mcp-governance-proxy-v0.1",
    policy: { ok: policyDecision.decision === "allow", decision: policyDecision.decision, reasons: policyReasons(policyDecision) },
    upstream: { ok: Boolean(upstreamResult) && !upstreamError, error: upstreamError, error_category: upstreamError ? categorizeUpstreamError(upstreamError) : null }
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
      sql_digest: policySqlDigest(policyDecision),
      input_digest: digestValue(request.input || {})
    },
    policy: {
      tier: "level-2-policy",
      decision: policyDecision.decision,
      reasons: policyReasons(policyDecision),
      policy_id: policyDecision.policy_id,
      policy_epoch_id: policyDecision.policy_epoch_id,
      policy_bundle_version: policyBundle.version,
      policy_bundle_digest: policyDecision.policy_bundle_digest,
      policy_witness_quorum: `${policyDecision.allow_count}-of-${policyDecision.total_witnesses}`,
      policy_quorum_threshold: policyDecision.threshold,
      policy_quorum_version: policyDecision.version,
      decision_digests: policyDecision.decisions.map((decision) => digestValue({ subject: decision.subject, signature: decision.signature })),
      rule_results: policyRuleResults(policyDecision)
    },
    proof: {
      assurance_mode: witnessed ? "witnessed" : "mcp-governance-proxy-phase1-scaffold",
      witness_tiers: ["level-1-mechanical", "level-2-policy"],
      mechanical_witness_quorum: `${config.witness.threshold}-of-${config.witnesses.length}`,
      policy_witness_quorum: `${policyDecision.allow_count}-of-${policyDecision.total_witnesses}`,
      side_effect_executed: Boolean(upstreamResult) && !denied,
      verified: verification.ok,
      ...(witnessed ? {
        receipt_count: witnessed.receipts.length,
        checkpoint_id: witnessed.checkpoint.statement.checkpoint_id,
        receipt_root: witnessed.session.finalStateRoot
      } : {}),
      note: witnessed
        ? "Supabase action executed through ActionGateway with Level 1 mechanical witness receipts and signed Level 2 policy quorum."
        : "Supabase actions require signed Level 2 policy quorum before upstream execution. Full Level 1 receipt wiring will follow the email gateway ActionGateway path."
    },
    admission: witnessed?.admissionManifest ? operatorAdmissionCertificateBinding(witnessed.admissionManifest, { operatorRegistryBinding: witnessed.operatorRegistryBinding }) : null,
    operator_identity: witnessed?.admissionManifest ? operatorIdentityCertificateBinding(witnessed.admissionManifest, { operatorRegistryBinding: witnessed.operatorRegistryBinding }) : null,
    registry: registryCertificateBinding(witnessed?.registryBinding || null),
    authority_pins: authorityPins(config, witnessed?.registryBinding || null, policyBundle),
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

  const durablePublication = await publishDurableBundle(config, { runId, runDir: outDir, certificateDigest });
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
    error_category: denied ? "policy_denied" : (upstreamError ? categorizeUpstreamError(upstreamError) : null),
    errors: certificate.errors
  };
}

function policyReasons(policyQuorum) {
  return policyQuorum.deny_reasons || [...new Set((policyQuorum.decisions || []).flatMap((decision) => decision.subject?.reasons || []))];
}

function policyRuleResults(policyQuorum) {
  return policyQuorum.decisions?.[0]?.subject?.rule_results || [];
}

function policySqlDigest(policyQuorum) {
  return policyQuorum.decisions?.find((decision) => decision.subject?.sql_digest)?.subject.sql_digest || null;
}

function artifactPaths(outDir) {
  return {
    receipts: join(outDir, "receipts.jsonl"),
    keyring: join(outDir, "keyring.json"),
    checkpoint: join(outDir, "checkpoint.json"),
    transparencyLog: join(outDir, "transparency-log.jsonl"),
    verification: join(outDir, "verification.json"),
    admissionManifest: join(outDir, "admission-manifest.json"),
    operatorRegistry: join(outDir, "operator-registry.json"),
    policyDecision: join(outDir, "policy-decision.json"),
    policyBundle: join(outDir, "policy-bundle.json"),
    registryEpoch: join(outDir, "registry-epoch.json"),
    connectorManifest: join(outDir, "connector-manifest.json"),
    supabaseRequest: join(outDir, "supabase-request.json"),
    supabaseResultMetadata: join(outDir, "supabase-result-metadata.json")
  };
}

function loadGatewayKeys(config) {
  const keyDir = join(config.dataDir, "keys");
  mkdirSync(keyDir, { recursive: true });
  return {
    gateway: loadOrCreateEd25519Signer({
      keyFile: config.gateway.keyJson || config.gateway.privateKeyPem ? null : config.gateway.keyFile || join(keyDir, "gateway.key.json"),
      keyId: config.gateway.keyId,
      keyJson: config.gateway.keyJson,
      privateKeyPem: config.gateway.privateKeyPem,
      publicKeyPem: config.gateway.publicKeyPem
    }),
    tool: loadOrCreateEd25519Signer({ keyFile: join(keyDir, "supabase-tool.key.json"), keyId: "tool:supabase-mcp:supabase-mcp" }),
    transparency: loadOrCreateEd25519Signer({ keyFile: join(keyDir, "supabase-transparency.key.json"), keyId: "transparency:supabase-mcp" })
  };
}

async function createWitnessClients(specs, keyring, config, gatewaySigner) {
  const witnesses = specs.map((spec) => new HttpWitnessClient({
    ...spec,
    signedRequests: config.witness.signedRequests.enabled ? {
      enabled: true,
      gatewayId: config.gateway.id,
      gatewayKeyId: gatewaySigner.keyId,
      gatewaySigner,
      witnessId: spec.witnessId ?? spec.id,
      witnessEpochId: witnessEpochIdForSpec({ spec, config }),
      registryEpochId: registryEpochIdForSpec({ spec, config }),
      workflowId: workflowIdForSpec({ spec, config })
    } : null
  }));
  for (const witness of witnesses) {
    const publicKey = await witness.publicKey();
    witness.publicKeyInfo = publicKey;
    keyring[publicKey.key_id] = publicKey.public_key_pem;
  }
  return witnesses;
}

function l1WitnessEvidenceForSpec({ spec, config }) {
  return (config.attestation?.l1Witnesses || []).find((item) => item.witnessId === spec.id || item.witnessId === spec.witnessId);
}

function witnessEpochIdForSpec({ spec, config }) {
  return spec.witnessEpochId || l1WitnessEvidenceForSpec({ spec, config })?.witnessEpochId || config.witness.signedRequests.witnessEpochId;
}

function registryEpochIdForSpec({ spec, config }) {
  return spec.registryEpochId || l1WitnessEvidenceForSpec({ spec, config })?.registryEpochId || config.witness.signedRequests.registryEpochId;
}

function workflowIdForSpec({ spec, config }) {
  return spec.workflowId || l1WitnessEvidenceForSpec({ spec, config })?.workflowId || config.witness.signedRequests.workflowId;
}

function verifyConfiguredL1WitnessSetAuthority({ witnesses, registryBinding, policyHash, threshold }) {
  const registryEpoch = registryBinding?.epoch || null;
  const checks = witnesses.map((witness) => {
    const publicKey = witness.publicKeyInfo || {};
    const entry = (registryEpoch?.witnesses || []).find((candidate) => candidate.key_id === publicKey.key_id);
    const errors = [];
    if (!entry) {
      errors.push(`witness key ${publicKey.key_id || witness.id} is not in registry epoch`);
    } else {
      if (entry.witness_id !== witness.id) errors.push(`witness_id mismatch: expected ${witness.id}, got ${entry.witness_id}`);
      if (!(entry.authorized_workflows || []).includes(witness.signedRequests?.workflowId)) errors.push(`${entry.key_id} is not authorized for workflow ${witness.signedRequests?.workflowId}`);
      if (!(entry.authorized_policy_hashes || []).includes(policyHash)) errors.push(`${entry.key_id} is not authorized for policy ${policyHash}`);
      if (entry.tier !== "mechanical") errors.push(`witness tier must be mechanical, got ${entry.tier || "missing"}`);
    }
    return { witness_id: witness.id, witness_key_id: publicKey.key_id || null, ok: errors.length === 0, errors };
  });
  const authorized = checks.filter((check) => check.ok).length;
  return { ok: authorized >= threshold, authorized, threshold, checks, errors: checks.flatMap((check) => check.errors.map((error) => `${check.witness_id}: ${error}`)) };
}

async function loadAndWriteRegistryBinding(config, registryEpochPath) {
  if (!config.registry?.url) return null;
  const binding = await fetchRegistryBinding(config.registry.url, registryPinOptions(config));
  writeJson(registryEpochPath, {
    registry_epoch: binding.epoch,
    registry_epoch_digest: binding.epoch_digest,
    registry_epoch_url: binding.epoch_url,
    registry_trust_anchor: binding.trust_anchor,
    fetched_registry_trust_anchor: binding.fetched_trust_anchor,
    pinned: binding.pinned,
    verification: binding.verification
  });
  return binding;
}

async function loadAndWriteOperatorRegistryBinding(config, operatorRegistryPath, admissionManifest) {
  if (!config.registry?.url || !admissionManifest?.operator_signature?.operator_id) return null;
  const binding = await fetchOperatorRegistryBinding(config.registry.url, admissionManifest.operator_signature.operator_id, registryPinOptions(config));
  writeJson(operatorRegistryPath, binding);
  return binding;
}

function createSignedSupabaseAdmissionManifest({ config, requestContext, policyBundle, policyHash, egressPolicy }) {
  const tenantId = requestContext?.session?.tid || config.tenant.id;
  const operatorSigner = loadOperatorAdmissionSigner(config);
  const unsignedManifest = {
    ...createAdmissionManifest({
      manifestId: `adm_supabase_mcp_${tenantId}_v1`,
      governanceId: "gov_supabase_mcp_v1",
      policyHash,
      agent: tinfoilEvidence(null, "mcp-agent", ["mcp://tools/*"], null),
      gateway: tinfoilEvidence(config.attestation?.gateway, "supabase-gateway", ["strata://verified-actions/supabase.query"], egressPolicy),
      verifier: tinfoilEvidence(null, "supabase-verifier", ["verify://local/supabase"], null),
      approvedTools: [{ tool_id: "supabase-mcp", audience: "supabase-mcp", methods: ["MCP tools/call"] }],
      approvedDataSources: [{ source_id: "supabase-hosted-mcp", origin: upstreamOrigin(config), project_ref: config.supabase.projectRef, read_only: config.supabase.readOnly }],
      approvedModels: [],
      witnessSetId: "witness-set.supabase-mcp.l1+l2",
      witnessThreshold: config.witness.threshold
    }),
    workflow_id: "supabase.query",
    tenant_id: tenantId,
    operator_id: config.operator.id,
    active_policy: {
      policy_id: policyBundle.policy_id,
      policy_epoch_id: policyBundle.epoch_id,
      policy_bundle_version: policyBundle.version,
      policy_bundle_digest: supabasePolicyBundleDigest(policyBundle),
      policy_url: null
    },
    auth_context: admissionAuthContext(requestContext, tenantId)
  };
  return attachOperatorSignature(unsignedManifest, { signer: operatorSigner.signer, publicKeyPem: operatorSigner.publicKeyPem, operatorId: config.operator.id, tenantId });
}

function admissionAuthContext(requestContext, tenantId) {
  const session = requestContext?.session;
  if (!session) return { auth_method: "none", tenant_id: tenantId };
  return { auth_method: session.auth_method || "mcp-session", tenant_id: session.tid || tenantId, client_id: session.aid || null, scope: session.scope || null };
}

function policyQuorumInput(policyQuorum) {
  return {
    type: "policy.quorum",
    version: policyQuorum.version,
    tier: "level-2-policy",
    decision: policyQuorum.decision,
    policy_id: policyQuorum.policy_id,
    policy_epoch_id: policyQuorum.policy_epoch_id,
    policy_bundle_digest: policyQuorum.policy_bundle_digest,
    threshold: policyQuorum.threshold,
    allow_count: policyQuorum.allow_count,
    deny_count: policyQuorum.deny_count,
    total_witnesses: policyQuorum.total_witnesses,
    decision_digests: policyQuorum.decisions.map((decision) => digestValue({ subject: decision.subject, signature: decision.signature }))
  };
}

function verifyPolicyBundleForQuorum(policyBundle, policyQuorum) {
  const errors = [];
  const policyBundleDigestValue = policyBundle ? supabasePolicyBundleDigest(policyBundle) : null;
  if (!policyBundle) errors.push("policy bundle artifact missing");
  if (policyBundleDigestValue !== policyQuorum.policy_bundle_digest) errors.push(`policy bundle digest mismatch: bundle=${policyBundleDigestValue} quorum=${policyQuorum.policy_bundle_digest}`);
  if (policyBundle?.epoch_id !== policyQuorum.policy_epoch_id) errors.push(`policy epoch mismatch: bundle=${policyBundle?.epoch_id} quorum=${policyQuorum.policy_epoch_id}`);
  return { ok: errors.length === 0, errors, policy_id: policyBundle?.policy_id || null, policy_epoch_id: policyBundle?.epoch_id || null, policy_bundle_digest: policyBundleDigestValue };
}

function verifyRegistryAuthority({ receipts, checkpoint, keyring, policyQuorum, registryBinding }) {
  const trustAnchors = { [registryBinding.trust_anchor.key_id]: registryBinding.trust_anchor.public_key_pem };
  const l1Mechanical = verifyWitnessAuthority({ receipts, checkpoint, keyring, registryEpoch: registryBinding.epoch, trustAnchors, workflowId: "supabase.query", policyHash: policyQuorum.policy_bundle_digest, requiredTier: "mechanical" });
  const l2Policy = verifyPolicyQuorumAuthority({ policyQuorum, registryEpoch: registryBinding.epoch, workflowId: "supabase.query", policyHash: policyQuorum.policy_bundle_digest, requiredTier: "policy" });
  const errors = [...registryBinding.verification.errors.map((error) => `registry epoch: ${error}`), ...l1Mechanical.errors.map((error) => `l1 mechanical: ${error}`), ...l2Policy.errors.map((error) => `l2 policy: ${error}`)];
  return { ok: errors.length === 0, errors, registry_epoch_digest: registryBinding.epoch_digest, registry_epoch_id: registryBinding.epoch.epoch_id, registry_epoch_url: registryBinding.epoch_url, registry_authority_key_id: registryBinding.trust_anchor.key_id, l1_mechanical: l1Mechanical, l2_policy: l2Policy };
}

function operatorIdentityCertificateBinding(admissionManifest, { operatorRegistryBinding = null } = {}) {
  const verification = verifyOperatorAdmissionManifest(admissionManifest, { operatorRegistryBinding });
  const operatorRecord = operatorRegistryBinding?.operator_record || null;
  return {
    version: "strata.operator_identity_binding.v1",
    tenant_id: verification.tenant_id,
    operator_id: verification.operator_id,
    operator_key_id: verification.operator_key_id,
    operator_registry_url: verification.operator_registry_url,
    operator_registry_record_digest: verification.operator_registry_record_digest,
    registry_authority_key_id: verification.operator_registry_authority_key_id,
    admission_manifest_digest: verification.signed_manifest_digest,
    admission_signed_at: verification.signed_at,
    workflow_id: "supabase.query",
    tool_id: "supabase-mcp",
    policy_hash: verification.policy_hash,
    authorized_workflows: operatorRecord?.authorized_workflows || [],
    authorized_tools: operatorRecord?.authorized_tools || [],
    authorized_policy_hashes: operatorRecord?.authorized_policy_hashes || [],
    status_at_action_time: operatorRecord?.status || null,
    registry_authorized: verification.registry_authorized,
    signature_verified: verification.ok
  };
}

function registryCertificateBinding(registryBinding) {
  if (!registryBinding) return null;
  return { registry_epoch_id: registryBinding.epoch.epoch_id, registry_epoch_digest: registryBinding.epoch_digest, registry_epoch_url: registryBinding.epoch_url, registry_authority_key_id: registryBinding.trust_anchor.key_id, policy_bundle_digest: registryBinding.epoch.policy_bundle_digest, policy_bundle_url: registryBinding.epoch.policy_bundle_url || null, pinned: registryBinding.pinned || null };
}

function authorityPins(config, registryBinding, policyBundle) {
  const policyDigest = policyBundle ? supabasePolicyBundleDigest(policyBundle) : null;
  return {
    registry_epoch: { expected_digest: config.registry?.expectedEpochDigest || null, actual_digest: registryBinding?.epoch_digest || null, pinned: Boolean(config.registry?.expectedEpochDigest), matched: config.registry?.expectedEpochDigest ? config.registry.expectedEpochDigest === registryBinding?.epoch_digest : null },
    registry_trust_anchor: { expected_key_id: config.registry?.trustAnchorKeyId || null, actual_key_id: registryBinding?.trust_anchor?.key_id || null, pinned: Boolean(config.registry?.trustAnchorKeyId && config.registry?.trustAnchorPublicKeyPem), matched: config.registry?.trustAnchorKeyId ? config.registry.trustAnchorKeyId === registryBinding?.trust_anchor?.key_id : null },
    policy_bundle: { expected_digest: null, actual_digest: policyDigest, pinned: false, matched: null }
  };
}

async function publishDurableBundle(config, { runId, runDir, certificateDigest }) {
  const location = createDurableBundleLocation(config, { runId, certificateDigest });
  if (!location) return null;
  const publication = { ...location, status: "published" };
  const bundle = loadCertificateBundle({ config, runId, runDir, bundleUrl: publication.bundle_url, durablePublication: publication });
  return publishCertificateBundle(config, { runId, certificateDigest, bundle, durablePublication: publication });
}

function createEgressPolicy(config) {
  const allowedUrls = [...config.witnesses, ...config.policyWitnesses].map((witness) => witness.url);
  if (config.registry?.url) allowedUrls.push(config.registry.url);
  if (config.supabase.mcpBaseUrl) allowedUrls.push(upstreamOrigin(config));
  return { mode: "supabase-mcp-readonly-witness-and-registry-urls-only", allowed_urls: allowedUrls.sort(), enforcement: "application-code-typed-adapters" };
}

function tinfoilEvidence(evidence, containerName, shimPaths, egressPolicy) {
  return createTinfoilEvidence({
    containerName: evidence?.containerName || containerName,
    imageDigest: evidence?.imageDigest || `sha256:${sha256Hex(`supabase-mcp:${containerName}`)}`,
    configHash: evidence?.attestationDigest || sha256Hex(`supabase-mcp-config:${containerName}`),
    attestationRef: evidence?.attestationRef || evidence?.attestationUrl || `demo://supabase-mcp/${containerName}/attestation-placeholder`,
    sigstoreBundleRef: evidence?.sigstoreBundleRef || null,
    shimPaths,
    egressPolicy
  });
}

function registryPinOptions(config) {
  return { expectedEpochDigest: config.registry?.expectedEpochDigest || "", trustAnchorKeyId: config.registry?.trustAnchorKeyId || "", trustAnchorPublicKeyPem: config.registry?.trustAnchorPublicKeyPem || "" };
}

function supabaseClientHints(config) {
  const liveMode = config.supabase.toolResultMode || "summary";
  return {
    version: "strata.connector_client_hints.v1",
    upstream_capabilities: ["sql:read", "schema:inspect", "docs:search"],
    upstream_tool_mappings: {
      supabase_list_tables_verified: "list_tables",
      supabase_inspect_schema_verified: "execute_sql",
      supabase_query_readonly_verified: "execute_sql",
      supabase_search_docs: "search_docs"
    },
    semantic_input_hints: {
      supabase_query_readonly_verified: {
        query: "Single read-only SQL statement. The field is named query to match upstream MCP conventions, but semantically it carries SQL."
      },
      supabase_search_docs: {
        graphql_query: "GraphQL query string for Supabase docs search. The wrapper also accepts query as an alias."
      }
    },
    evidence_mode_per_tool: Object.fromEntries(["supabase_list_tables_verified", "supabase_inspect_schema_verified", "supabase_query_readonly_verified", "supabase_search_docs"].map((tool) => [tool, {
      durable_bundle: config.supabase.evidenceMode,
      live_response: liveMode,
      raw_result_in_durable_bundle: false
    }])),
    upstream_safety_features: [
      "supabase_prompt_injection_boundary_markers",
      "untrusted_data_delimiters",
      "upstream_read_only_mode"
    ],
    error_taxonomy: {
      policy_denied: "Strata policy denied before upstream execution.",
      upstream_auth_failure: "Supabase rejected the connector token, scopes, resource, or organization/project authorization.",
      upstream_validation_error: "Supabase MCP rejected the upstream tool arguments.",
      upstream_unavailable: "Supabase MCP was unavailable or returned a 5xx response.",
      gateway_internal_error: "The Strata gateway failed before producing a valid upstream request."
    },
    skill_boundary: "Connector hints are protocol-level affordances. Product/schema-specific query recipes, such as Hey Jil table joins, belong in client-side skills."
  };
}

function categorizeUpstreamError(error) {
  const value = String(error || "").toLowerCase();
  if (value.includes(" 401") || value.includes(" 403") || value.includes("unauthorized") || value.includes("forbidden") || value.includes("scope")) {
    return "upstream_auth_failure";
  }
  if (value.includes(" 400") || value.includes("invalid input") || value.includes("unrecognized key") || value.includes("validation")) {
    return "upstream_validation_error";
  }
  if (value.includes(" 500") || value.includes(" 502") || value.includes(" 503") || value.includes(" 504") || value.includes("unavailable")) {
    return "upstream_unavailable";
  }
  return "gateway_internal_error";
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
    receipts: `${base}/receipts.jsonl`,
    keyring: `${base}/keyring.json`,
    checkpoint: `${base}/checkpoint.json`,
    transparency_log: `${base}/transparency-log.jsonl`,
    admission_manifest: `${base}/admission-manifest.json`,
    operator_registry: `${base}/operator-registry.json`,
    registry_epoch: `${base}/registry-epoch.json`,
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

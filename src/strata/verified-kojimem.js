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
  verifyCheckpoint,
  verifySession,
  writeCheckpoint
} from "./primitives.js";
import { attachOperatorSignature, loadOperatorAdmissionSigner, operatorAdmissionCertificateBinding, verifyOperatorAdmissionManifest } from "../admission/operator-manifest.js";
import { loadCertificateBundle } from "../certificates/bundle.js";
import { createDurableBundleLocation, publishCertificateBundle } from "../certificates/publisher.js";
import { KojimemAgentClient } from "../kojimem/client.js";
import {
  KOJIMEM_ACTION_CERTIFICATE_VERSION,
  KOJIMEM_ACTION_REGISTRY_VERSION,
  KOJIMEM_GATEWAY_METHOD,
  KOJIMEM_GATEWAY_TOOL,
  KOJIMEM_MCP_TOOL,
  KOJIMEM_WORKFLOW_ID,
  connectorManifestDigest,
  createKojimemConnectorManifest,
  createKojimemHandoffRequest,
  l3AttestationSummary,
  summarizeExecutionOutput
} from "../kojimem/canonical.js";
import { createKojimemHandoffTool } from "../kojimem/tool.js";
import { collectKojimemPolicyQuorum, defaultKojimemPolicyBundle, kojimemPolicyBundleDigest } from "../policy/kojimem-policy.js";

export async function createKojimemActionRegistry(config) {
  const manifest = createKojimemConnectorManifest(config);
  const policyBundle = defaultKojimemPolicyBundle(config);
  return {
    version: KOJIMEM_ACTION_REGISTRY_VERSION,
    registry_id: "action-registry.kojimem-agent-handoff",
    epoch_id: "kojimem-agent-handoff-epoch-v1",
    connector_manifest_digest: connectorManifestDigest(config),
    protocol: kojimemProtocolVersions(),
    tools: kojimaTools(config),
    actions: manifest.tools.map((tool) => ({
      action_id: `agent_handoff.${tool.strata_tool}`,
      mcp_tool_name: tool.strata_tool,
      gateway_tool_name: tool.gateway_tool,
      assurance: {
        mode: "witnessed-agentic-transaction",
        required_witness_tiers: ["mechanical", "policy"],
        optional_witness_tiers: ["domain-attestor"],
        mechanical_quorum: { threshold: config.witness.threshold, set: "witness-set.kojimem-agent-handoff.l1" },
        policy_quorum: { threshold: config.policyWitness.threshold, set: "witness-set.kojimem-agent-handoff.l2-policy" }
      },
      policy: {
        policy_bundle_hash: digestValue(policyBundle),
        policy_bundle_version: policyBundle.version,
        policy_epoch_id: policyBundle.epoch_id,
        policy_summary: policyBundle.rules
      },
      adapter: {
        adapter_id: "kojimem-x402-api",
        implementation: "Attexa Kojimem x402 backpack governance proxy",
        upstream_origin: config.kojimem.apiBaseUrl
      },
      persisted_payload_policy: "digest-first-fraud-signal-handoff"
    }))
  };
}

export async function kojimemGatewayStatus(config) {
  const policyBundle = defaultKojimemPolicyBundle(config);
  const missing = [];
  if (!config.kojimem.agentAPrivateKey) missing.push("KOJIMEM_AGENT_A_PRIVATE_KEY");
  if (!config.kojimem.agentBPrivateKey) missing.push("KOJIMEM_AGENT_B_PRIVATE_KEY");
  if (!config.kojimem.agentAAccount?.address) missing.push("Agent A wallet account");
  if (!config.kojimem.agentBAccount?.address) missing.push("Agent B wallet account");
  return {
    status: missing.length === 0 ? "ready" : "setup_required",
    checked_at: new Date().toISOString(),
    protocol: kojimemProtocolVersions(),
    connector: publicConnectorBinding(config),
    policy: {
      policy_id: policyBundle.policy_id,
      policy_epoch_id: policyBundle.epoch_id,
      policy_bundle_version: policyBundle.version,
      policy_bundle_digest: digestValue(policyBundle),
      rules: policyBundle.rules
    },
    assurance: {
      mode: "witnessed-agentic-transaction",
      witness_tiers: ["level-1-mechanical", "level-2-policy", "optional-level-3-domain"],
      mechanical_witness_quorum_required: `${config.witness.threshold}-of-${config.witnesses.length}`,
      policy_witness_quorum_required: `${config.policyWitness.threshold}-of-${config.policyWitnesses.length}`,
      note: "Live Kojimem handoffs execute through ActionGateway with signed Level 1 receipts and signed Level 2 policy quorum. L3 domain attestation is required when policy exposure thresholds are exceeded."
    },
    missing
  };
}

export async function runVerifiedKojimemHandoff({ input, config, requestContext = {} }) {
  if (config.witnesses.length < config.witness.threshold) {
    throw new Error(`Kojimem handoff requires at least ${config.witness.threshold} Level 1 witness URL(s) in WITNESS_URLS`);
  }
  if (config.policyWitnesses.length < config.policyWitness.threshold) {
    throw new Error(`Kojimem handoff requires at least ${config.policyWitness.threshold} Level 2 policy witness URL(s) in POLICY_WITNESS_URLS`);
  }

  const runId = `kojimem_${Date.now()}_${randomUUID().slice(0, 8)}`;
  const outDir = join(config.dataDir, "runs", runId);
  const certificateUrl = `${config.certificateBaseUrl}/${runId}`;
  mkdirSync(outDir, { recursive: true });
  const paths = artifactPaths(outDir);
  const { request, executionInput, publicCommitment } = createKojimemHandoffRequest(input, config);
  const redactedRequest = redactRequestForArtifact(request);

  const policyBundle = defaultKojimemPolicyBundle(config);
  const policyDecision = await collectKojimemPolicyQuorum({
    witnesses: config.policyWitnesses,
    request,
    input: executionInput,
    config,
    policyBundle,
    threshold: config.policyWitness.threshold
  });
  writeJson(paths.connectorManifest, createKojimemConnectorManifest(config));
  writeJson(paths.policyBundle, policyBundle);
  writeJson(paths.policyDecision, policyDecision);
  writeJson(paths.kojimemRequest, redactedRequest);

  if (policyDecision.decision !== "allow") {
    return writeKojimemCertificate({
      config,
      runId,
      outDir,
      certificateUrl,
      requestContext,
      request,
      redactedRequest,
      l3Attestation: executionInput.l3_attestation,
      publicCommitment,
      policyBundle,
      policyDecision,
      output: null,
      denied: true
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

  const log = new JsonlReceiptLog(paths.receipts);
  log.reset();
  const transparencyLog = new LocalTransparencyLog({
    filePath: paths.transparencyLog,
    signer: keys.transparency.signer,
    logId: "kojimem-agent-handoff-transparency-log"
  });
  transparencyLog.reset();

  const verifierProfile = createVerifierProfile({ profile_id: "profile.kojimem-agent-handoff.l1-l2-l3.v1" });
  const policyHash = policyDecision.policy_bundle_digest;
  const admissionManifest = createSignedKojimemAdmissionManifest({ config, requestContext, policyBundle, policyHash, egressPolicy: createEgressPolicy(config) });
  writeJson(paths.admissionManifest, admissionManifest);
  const tool = createKojimemHandoffTool({
    signer: keys.tool.signer,
    gatewayKeyring: keyring,
    agentAClient: new KojimemAgentClient({ apiBaseUrl: config.kojimem.apiBaseUrl, account: config.kojimem.agentAAccount, timeoutMs: config.kojimem.timeoutMs }),
    agentBClient: new KojimemAgentClient({ apiBaseUrl: config.kojimem.apiBaseUrl, account: config.kojimem.agentBAccount, timeoutMs: config.kojimem.timeoutMs })
  });
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

  await gateway.startSession({ sessionId: `sess_${runId}`, taskInputDigest: publicCommitment.request_digest });
  const toolResult = await gateway.toolCall({
    toolName: KOJIMEM_GATEWAY_TOOL,
    method: KOJIMEM_GATEWAY_METHOD,
    request,
    inputEdges: [policyQuorumInput(policyDecision)]
  });
  await gateway.endSession(toolResult.output.status === "completed" ? "complete" : "upstream_error");
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
  const operatorAdmission = verifyOperatorAdmissionManifest(admissionManifest, { requireRegistry: false });
  const verified = session.ok && checkpointResult.ok && policyBundleVerification.ok && operatorAdmission.ok && toolResult.output.status === "completed";
  const verification = { ok: verified, session, checkpoint: checkpointResult, policy_bundle: policyBundleVerification, operator_admission: operatorAdmission };
  writeJson(paths.verification, verification);
  writeJson(paths.kojimemResultMetadata, summarizeExecutionOutput(toolResult.output));

  return writeKojimemCertificate({
    config,
    runId,
    outDir,
    certificateUrl,
    requestContext,
    request,
    redactedRequest,
    l3Attestation: executionInput.l3_attestation,
    publicCommitment,
    policyBundle,
    policyDecision,
    output: toolResult.output,
    denied: false,
    witnessed: {
      receipts,
      checkpoint,
      session,
      checkpointResult,
      policyBundleVerification,
      operatorAdmission,
      admissionManifest,
      verified
    }
  });
}

async function writeKojimemCertificate({ config, runId, outDir, certificateUrl, requestContext, request, redactedRequest, l3Attestation, publicCommitment, policyBundle, policyDecision, output, denied, witnessed = null }) {
  const resultSummary = output ? summarizeExecutionOutput(output) : null;
  const l3Summary = l3AttestationSummary(l3Attestation || null);
  const verification = {
    ok: witnessed ? witnessed.verified : false,
    phase: "kojimem-agent-handoff-v0.1",
    policy: { ok: policyDecision.decision === "allow", decision: policyDecision.decision, reasons: policyReasons(policyDecision) },
    execution: { ok: output?.status === "completed", status: output?.status || "not_executed" }
  };
  if (!witnessed) writeJson(join(outDir, "verification.json"), verification);
  if (!output) writeJson(join(outDir, "kojimem-result-metadata.json"), { status: denied ? "policy_denied" : "not_executed" });

  const certificateBody = {
    version: denied ? "strata.kojimem.policy_denial_certificate.v1" : KOJIMEM_ACTION_CERTIFICATE_VERSION,
    run_id: runId,
    certificate_url: certificateUrl,
    bundle_url: `${certificateUrl}/bundle`,
    issued_at: new Date().toISOString(),
    denied,
    action: {
      mcp_tool_name: KOJIMEM_MCP_TOOL,
      gateway_tool_name: KOJIMEM_GATEWAY_TOOL,
      method: KOJIMEM_GATEWAY_METHOD,
      workflow_id: KOJIMEM_WORKFLOW_ID
    },
    connector: publicConnectorBinding(config),
    request: {
      request_digest: digestValue(request),
      public_commitment: publicCommitment,
      redacted: redactedRequest
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
    l3_domain_attestation: l3Summary,
    proof: {
      assurance_mode: l3Summary ? "witnessed_with_l3" : "witnessed",
      witness_tiers: l3Summary ? ["level-1-mechanical", "level-2-policy", "level-3-domain"] : ["level-1-mechanical", "level-2-policy"],
      mechanical_witness_quorum: `${config.witness.threshold}-of-${config.witnesses.length}`,
      policy_witness_quorum: `${policyDecision.allow_count}-of-${policyDecision.total_witnesses}`,
      side_effect_executed: Boolean(output) && output.status === "completed" && !denied,
      verified: verification.ok,
      ...(witnessed ? {
        receipt_count: witnessed.receipts.length,
        checkpoint_id: witnessed.checkpoint.statement.checkpoint_id,
        receipt_root: witnessed.session.finalStateRoot
      } : {})
    },
    admission: witnessed?.admissionManifest ? operatorAdmissionCertificateBinding(witnessed.admissionManifest) : null,
    result: resultSummary,
    session: {
      tenant_id: config.tenant.id,
      operator_id: config.operator.id,
      assistant_id: requestContext.session?.aid || requestContext.session?.client_id || null
    },
    artifacts: publicArtifactUrls(config, runId),
    errors: [output?.error, ...policyDecision.errors.map((item) => item.error)].filter(Boolean)
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
    l3_domain_attestation: l3Summary,
    result: resultSummary,
    tool_result: output,
    error_category: denied ? "policy_denied" : (output?.error ? "kojimem_execution_error" : null),
    errors: certificate.errors
  };
}

function kojimemProtocolVersions() {
  return {
    certificate_schema_version: KOJIMEM_ACTION_CERTIFICATE_VERSION,
    connector_manifest_schema_version: "strata.kojimem.connector_manifest.v1",
    request_schema_version: "strata.kojimem.agent_handoff_request.v1",
    policy_bundle_schema_version: "strata.kojimem.policy_bundle.v1",
    policy_decision_schema_version: "strata.kojimem.policy_decision.v1"
  };
}

function kojimaTools(config) {
  return [
    {
      name: "gateway_status",
      title: "Check Attexa Agent Handoff Gateway Status",
      description: "Check Kojimem x402 backpack gateway configuration, server-side agent wallets, witness quorum, policy quorum, and L3 threshold policy.",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      annotations: { title: "Gateway status", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
    },
    {
      name: KOJIMEM_MCP_TOOL,
      title: "Run Witnessed Agent-to-Agent Fraud Signal Exchange",
      description: "Execute a live Kojimem x402 agentic transaction: Agent A creates an ephemeral fraud-signal backpack, delegates recall/destroy to Agent B, Agent B pays with USDC to recall and reason, then destroys the backpack. Attexa produces L1/L2 evidence and binds optional L3 domain attestation when the exposure threshold requires human approval.",
      inputSchema: {
        type: "object",
        properties: {
          case_id: { type: "string" },
          estimated_exposure_usd: { type: "number", default: config.kojimem.defaultEstimatedExposureUsd },
          ttl: { type: "string", enum: ["1h", "4h", "12h", "24h"], default: config.kojimem.defaultTtl },
          recall_tier: { type: "string", enum: ["fast", "balanced", "reasoning"], default: config.kojimem.defaultRecallTier },
          facts: { type: "array", items: { type: "string" } },
          recall_question: { type: "string" },
          l3_attestation: { type: "object", description: "Optional Level 3 domain attestation. Required when policy exposure threshold is exceeded." }
        },
        additionalProperties: false
      },
      annotations: { title: "Witnessed fraud signal exchange", readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
    }
  ];
}

function artifactPaths(outDir) {
  return {
    receipts: join(outDir, "receipts.jsonl"),
    keyring: join(outDir, "keyring.json"),
    checkpoint: join(outDir, "checkpoint.json"),
    transparencyLog: join(outDir, "transparency-log.jsonl"),
    verification: join(outDir, "verification.json"),
    admissionManifest: join(outDir, "admission-manifest.json"),
    policyDecision: join(outDir, "policy-decision.json"),
    policyBundle: join(outDir, "policy-bundle.json"),
    connectorManifest: join(outDir, "connector-manifest.json"),
    kojimemRequest: join(outDir, "kojimem-request.json"),
    kojimemResultMetadata: join(outDir, "kojimem-result-metadata.json")
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
    tool: loadOrCreateEd25519Signer({ keyFile: join(keyDir, "kojimem-tool.key.json"), keyId: `tool:kojimem:${KOJIMEM_GATEWAY_TOOL}` }),
    transparency: loadOrCreateEd25519Signer({ keyFile: join(keyDir, "kojimem-transparency.key.json"), keyId: "transparency:kojimem-agent-handoff" })
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
      witnessEpochId: spec.witnessEpochId || config.witness.signedRequests.witnessEpochId,
      registryEpochId: spec.registryEpochId || config.witness.signedRequests.registryEpochId,
      workflowId: spec.workflowId || config.witness.signedRequests.workflowId
    } : null
  }));
  for (const witness of witnesses) {
    const publicKey = await witness.publicKey();
    witness.publicKeyInfo = publicKey;
    keyring[publicKey.key_id] = publicKey.public_key_pem;
  }
  return witnesses;
}

function createSignedKojimemAdmissionManifest({ config, requestContext, policyBundle, policyHash, egressPolicy }) {
  const tenantId = requestContext?.session?.tid || config.tenant.id;
  const operatorSigner = loadOperatorAdmissionSigner(config);
  const unsignedManifest = {
    ...createAdmissionManifest({
      manifestId: `adm_kojimem_agent_handoff_${tenantId}_v1`,
      governanceId: "gov_kojimem_agent_handoff_v1",
      policyHash,
      agent: tinfoilEvidence(null, "mcp-agent", ["mcp://tools/*"], null),
      gateway: tinfoilEvidence(config.attestation?.gateway, "kojimem-agent-handoff-gateway", ["strata://verified-actions/agent-handoff.fraud-signal-exchange"], egressPolicy),
      verifier: tinfoilEvidence(null, "kojimem-verifier", ["verify://local/kojimem"], null),
      approvedTools: [{ tool_id: KOJIMEM_GATEWAY_TOOL, audience: KOJIMEM_GATEWAY_TOOL, methods: [KOJIMEM_GATEWAY_METHOD] }],
      approvedDataSources: [{ source_id: "kojimem-api", origin: config.kojimem.apiBaseUrl, auth: "x402+siwx+delegation" }],
      approvedModels: [],
      witnessSetId: "witness-set.kojimem-agent-handoff.l1+l2",
      witnessThreshold: config.witness.threshold
    }),
    workflow_id: KOJIMEM_WORKFLOW_ID,
    tenant_id: tenantId,
    operator_id: config.operator.id,
    active_policy: {
      policy_id: policyBundle.policy_id,
      policy_epoch_id: policyBundle.epoch_id,
      policy_bundle_version: policyBundle.version,
      policy_bundle_digest: kojimemPolicyBundleDigest(policyBundle),
      policy_url: null
    },
    auth_context: requestContext?.session ? { auth_method: requestContext.session.auth_method || "mcp-session", tenant_id: requestContext.session.tid || tenantId, client_id: requestContext.session.aid || null, scope: requestContext.session.scope || null } : { auth_method: "none", tenant_id: tenantId }
  };
  return attachOperatorSignature(unsignedManifest, { signer: operatorSigner.signer, publicKeyPem: operatorSigner.publicKeyPem, operatorId: config.operator.id, tenantId });
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
  const policyBundleDigestValue = policyBundle ? kojimemPolicyBundleDigest(policyBundle) : null;
  if (!policyBundle) errors.push("policy bundle artifact missing");
  if (policyBundleDigestValue !== policyQuorum.policy_bundle_digest) errors.push(`policy bundle digest mismatch: bundle=${policyBundleDigestValue} quorum=${policyQuorum.policy_bundle_digest}`);
  if (policyBundle?.epoch_id !== policyQuorum.policy_epoch_id) errors.push(`policy epoch mismatch: bundle=${policyBundle?.epoch_id} quorum=${policyQuorum.policy_epoch_id}`);
  return { ok: errors.length === 0, errors, policy_id: policyBundle?.policy_id || null, policy_epoch_id: policyBundle?.epoch_id || null, policy_bundle_digest: policyBundleDigestValue };
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
  if (config.kojimem.apiBaseUrl) allowedUrls.push(config.kojimem.apiBaseUrl);
  return { mode: "kojimem-x402-witness-and-policy-urls-only", allowed_urls: allowedUrls.sort(), enforcement: "application-code-typed-adapters" };
}

function tinfoilEvidence(evidence, containerName, shimPaths, egressPolicy) {
  return createTinfoilEvidence({
    containerName: evidence?.containerName || containerName,
    imageDigest: evidence?.imageDigest || `sha256:${sha256Hex(`kojimem:${containerName}`)}`,
    configHash: evidence?.attestationDigest || sha256Hex(`kojimem-config:${containerName}`),
    attestationRef: evidence?.attestationRef || evidence?.attestationUrl || `demo://kojimem/${containerName}/attestation-placeholder`,
    sigstoreBundleRef: evidence?.sigstoreBundleRef || tinfoilReleaseRef(evidence) || `sigstore://kojimem/${containerName}`,
    shimPaths,
    egressPolicy
  });
}

function tinfoilReleaseRef(evidence) {
  if (!evidence?.configRepo || !evidence?.configTag) return null;
  return `https://github.com/${evidence.configRepo}/releases/tag/${evidence.configTag}`;
}

function publicConnectorBinding(config) {
  return {
    connector_id: config.kojimem.connectorId,
    connector_label: config.kojimem.connectorLabel,
    connector_type: "kojimem_x402_backpack",
    auth_mode: "server-side-agent-wallets-x402-siwx-delegation",
    api_base_url: config.kojimem.apiBaseUrl,
    network: config.kojimem.network,
    agent_a_wallet: config.kojimem.agentAAccount?.address || null,
    agent_b_wallet: config.kojimem.agentBAccount?.address || null,
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
    connector_manifest: `${base}/connector-manifest.json`,
    policy_bundle: `${base}/policy-bundle.json`,
    policy_decision: `${base}/policy-decision.json`,
    kojimem_request: `${base}/kojimem-request.json`,
    kojimem_result_metadata: `${base}/kojimem-result-metadata.json`,
    verification: `${base}/verification.json`
  };
}

function redactRequestForArtifact(request) {
  const copy = JSON.parse(JSON.stringify(request));
  if (copy.execution) {
    copy.execution = {
      persona: copy.execution.persona,
      ttl: copy.execution.ttl,
      fact_count: Array.isArray(copy.execution.facts) ? copy.execution.facts.length : 0,
      facts_digest: copy.backpack?.facts_digest || null,
      recall_question_digest: copy.recall?.question_digest || null
    };
  }
  return copy;
}

function policyReasons(policyQuorum) {
  return policyQuorum.deny_reasons || [...new Set((policyQuorum.decisions || []).flatMap((decision) => decision.subject?.reasons || []))];
}

function policyRuleResults(policyQuorum) {
  return policyQuorum.decisions?.[0]?.subject?.rule_results || [];
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { assembleAttestationBundle, hashAttestationDocument } from "@tinfoilsh/verifier";
import {
  ActionGateway,
  HttpWitnessClient,
  JsonlReceiptLog,
  LocalTransparencyLog,
  canonicalize,
  createAdmissionManifest,
  createTinfoilEvidence,
  createVerifierProfile,
  digestValue,
  loadOrCreateEd25519Signer,
  sha256Hex,
  signEd25519,
  toolRequestDigest,
  verifyCheckpoint,
  verifySession,
  verifyWitnessAuthority,
  writeCheckpoint
} from "./primitives.js";
import { EMAIL_COMMITMENT_VERSION, EMAIL_PAYLOAD_VERSION, canonicalizeEmailInput, emailCommitment } from "../email/canonical.js";
import { createEmailProvider } from "../email/provider.js";
import { createEmailTool } from "../email/tool.js";
import {
  OPERATOR_ADMISSION_SIGNATURE_SUBJECT_VERSION,
  OPERATOR_ADMISSION_SIGNATURE_VERSION,
  attachOperatorSignature,
  loadOperatorAdmissionSigner,
  operatorAdmissionCertificateBinding,
  optionalOperatorAdmissionVerification,
  verifyOperatorAdmissionManifest
} from "../admission/operator-manifest.js";
import {
  EMAIL_POLICY_BUNDLE_VERSION,
  EMAIL_POLICY_DECISION_VERSION,
  EMAIL_POLICY_POINTER_VERSION,
  collectPolicyQuorum,
  loadEmailPolicyBundle,
  policyBundleMetadata,
  policyBundleDigest,
  verifyPolicyQuorumAuthority
} from "../policy/email-policy.js";
import { fetchOperatorRegistryBinding, fetchRegistryBinding } from "../registry/email-registry.js";

export async function createActionRegistry(config) {
  const policyBundle = await loadConfiguredPolicyBundle(config);
  const policyHash = policyBundleDigest(policyBundle);
  const policyUrl = configuredPolicyUrl(config, policyBundle);
  return {
    version: "strata.action-registry.v1",
    registry_id: "action-registry.email-mcp",
    epoch_id: "email-mcp-epoch-v1",
    protocol: emailProtocolVersions(),
    tools: [
      {
        name: "gateway_status",
        title: "Check Strata Gateway Status",
        description: "Check email provider configuration, Level 1 witness health, and Level 2 policy witness health before sending.",
        inputSchema: {
          type: "object",
          properties: {},
          additionalProperties: false
        },
        annotations: {
          title: "Gateway status",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: true
        }
      },
      {
        name: "email_preview",
        title: "Preview Email Commitment",
        description: "Canonicalize an email payload and return digest-first metadata without sending.",
        inputSchema: emailInputSchema(),
        annotations: {
          title: "Preview email digest",
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false
        }
      },
      {
        name: "email_send_verified",
        title: "Send Verified Email",
        description: `Send an email through the Strata Verified Action Gateway. Assurance mode: witnessed. Witness tiers: Level 1 mechanical + Level 2 policy. Quorum: ${config.witness.threshold}-of-${config.witnesses.length} L1 and ${config.policyWitness.threshold}-of-${config.policyWitnesses.length} L2.`,
        inputSchema: emailInputSchema(),
        outputSchema: {
          type: "object",
          properties: {
            status: { type: "string" },
            provider: { type: "string" },
            provider_message_id: { type: "string" },
            certificate_ref: { type: "string" },
            certificate_url: { type: "string" },
            certificate_digest: { type: "string" },
            witness_quorum: { type: "string" },
            verified: { type: "boolean" }
          },
          required: ["status", "provider", "certificate_ref", "certificate_digest", "verified"]
        },
        annotations: {
          title: "Verified email send",
          destructiveHint: true,
          idempotentHint: false,
          openWorldHint: true
        }
      },
      {
        name: "email_verify_received",
        title: "Verify Received Email",
        description: "Create a recipient-side verification receipt by comparing a received email to a Strata email certificate.",
        inputSchema: {
          type: "object",
          properties: {
            certificate_ref: { type: "string", description: "file:// certificate directory/file, local path, or configured certificate URL" },
            received: emailReceivedInputSchema()
          },
          required: ["certificate_ref", "received"],
          additionalProperties: false
        },
        annotations: {
          title: "Recipient verification receipt",
          readOnlyHint: false,
          destructiveHint: false,
          idempotentHint: false,
          openWorldHint: false
        }
      }
    ],
    actions: [
      {
        action_id: "email.send",
        mcp_tool_name: "email_send_verified",
        assurance: {
          mode: "witnessed",
          required_witness_tiers: ["mechanical", "policy"],
          mechanical_quorum: { threshold: config.witness.threshold, set: "witness-set.email-mcp.l1" },
          policy_quorum: { threshold: config.policyWitness.threshold, set: "witness-set.email-mcp.l2-policy" }
        },
        policy: {
          policy_bundle_hash: policyHash,
          policy_bundle_version: policyBundle.version,
          policy_epoch_id: policyBundle.epoch_id,
          policy_url: policyUrl || null,
          policy_summary: policyBundle.rules
        },
        adapter: { adapter_id: "resend-email-api", implementation: "Strata email adapter" },
        persisted_payload_policy: "digests-and-provider-metadata-only"
      }
    ]
  };
}

export function previewEmail(input, config) {
  const { publicCommitment } = emailCommitment(input, { from: config.email.from });
  return {
    ...publicCommitment,
    certificate_timing: "Certificate is produced only when email_send_verified executes the witnessed send action.",
    certificate_transmission: "The send tool injects Strata certificate metadata into X-Strata-* email headers and returns the same metadata in the MCP result."
  };
}

export async function gatewayStatus(config) {
  const witnessChecks = await Promise.all(config.witnesses.map(checkWitness));
  const policyWitnessChecks = await Promise.all(config.policyWitnesses.map(checkPolicyWitness));
  const healthyWitnesses = witnessChecks.filter((witness) => witness.ok).length;
  const healthyPolicyWitnesses = policyWitnessChecks.filter((witness) => witness.ok).length;
  const requiredWitnesses = config.witness.threshold;
  const requiredPolicyWitnesses = config.policyWitness.threshold;
  const policyBundle = await loadConfiguredPolicyBundle(config);
  const policyUrl = configuredPolicyUrl(config, policyBundle);
  const registry = await safeRegistryStatus(config);
  return {
    status: healthyWitnesses >= requiredWitnesses && healthyPolicyWitnesses >= requiredPolicyWitnesses && config.email.provider ? "ready" : "not_ready",
    checked_at: new Date().toISOString(),
    protocol: emailProtocolVersions(),
    assurance: {
      mode: "witnessed",
      witness_tiers: ["level-1-mechanical", "level-2-policy"],
      mechanical_witness_quorum_required: `${requiredWitnesses}-of-${config.witnesses.length}`,
      mechanical_witness_quorum_available: `${healthyWitnesses}-of-${config.witnesses.length}`,
      signed_l1_witness_requests: config.witness.signedRequests.enabled,
      signed_l1_witness_workflow_id: config.witness.signedRequests.workflowId || null,
      policy_witness_quorum_required: `${requiredPolicyWitnesses}-of-${config.policyWitnesses.length}`,
      policy_witness_quorum_available: `${healthyPolicyWitnesses}-of-${config.policyWitnesses.length}`
    },
    policy: {
      policy_bundle_version: policyBundle.version,
      policy_id: policyBundle.policy_id,
      policy_epoch_id: policyBundle.epoch_id,
      policy_bundle_digest: policyBundleDigest(policyBundle),
      policy_url: policyUrl || null,
      rules: policyBundle.rules
    },
    operator_admission: {
      tenant_id: config.tenant.id,
      operator_id: config.operator.id,
      operator_key_id: config.operator.admissionKeyId,
      manifest_scope: "tenant/default active email.send admission manifest",
      signature_schema_version: OPERATOR_ADMISSION_SIGNATURE_VERSION
    },
    registry,
    policy_witness_signing: policyWitnessSigningSemantics(),
    receipt_flow: emailReceiptFlow(),
    denial_receipt_flow: policyDenialReceiptFlow(),
    email_provider: {
      provider: config.email.provider,
      from_configured: Boolean(config.email.from),
      resend_configured: config.email.provider !== "resend" || Boolean(config.email.resendApiKey)
    },
    certificate_channel: {
      produced_at: "email_send_verified execution time",
      in_band_headers: [
        "X-Strata-Action-Id",
        "X-Strata-Payload-Digest",
        "X-Strata-Certificate-URL",
        "X-Strata-Witness-Tier"
      ],
      header_semantics: {
        "X-Strata-Action-Id": "The pre-send IntentGrant grant_id. It identifies the gateway authorization that permitted this exact email send.",
        "X-Strata-Payload-Digest": "Digest of the canonical email commitment under protocol.commitment_schema_version.",
        "X-Strata-Certificate-URL": "Public URL for the post-send certificate bundle.",
        "X-Strata-Witness-Tier": "Assurance tier used for the witnessed send."
      },
      mcp_result_fields: ["certificate_url", "certificate_digest", "payload_digest", "receipt_root", "checkpoint_id"]
    },
    witnesses: witnessChecks,
    policy_witnesses: policyWitnessChecks
  };
}

function emailProtocolVersions() {
  return {
    commitment_schema_version: EMAIL_COMMITMENT_VERSION,
    payload_schema_version: EMAIL_PAYLOAD_VERSION,
    certificate_schema_version: "strata.email.certificate.v1",
    recipient_verification_schema_version: "strata.recipient.verification_receipt.v1",
    policy_bundle_schema_version: EMAIL_POLICY_BUNDLE_VERSION,
    policy_decision_schema_version: EMAIL_POLICY_DECISION_VERSION,
    policy_pointer_schema_version: EMAIL_POLICY_POINTER_VERSION,
    operator_admission_signature_schema_version: OPERATOR_ADMISSION_SIGNATURE_VERSION,
    operator_admission_signature_subject_schema_version: OPERATOR_ADMISSION_SIGNATURE_SUBJECT_VERSION,
    policy_quorum_schema_version: "strata.email.policy_quorum.v1"
  };
}

function emailReceiptFlow() {
  return {
    expected_receipt_count: 6,
    note: "receipt_count counts hash-chained protocol receipts, not the number of witnesses. L1 witness signatures are embedded in quorum certificates on selected receipts. L2 policy signatures are separate policy decision artifacts whose digests are embedded into the intent.grant typed inputs.",
    steps: [
      { index: 0, kind: "session.start", purpose: "Open certified session and bind policy/admission evidence." },
      { index: 1, kind: "tool.request", purpose: "Commit to the requested email send digest before authorization." },
      { index: 2, kind: "intent.grant", purpose: "Gateway grants a single-use capability for this exact send; Level 1 witnesses sign the grant subject, and the grant typed_inputs embed the Level 2 policy quorum digest set." },
      { index: 3, kind: "tool.execution", purpose: "Email adapter verifies the capability, sends via provider, and signs provider message metadata." },
      { index: 4, kind: "observation", purpose: "Gateway observes the tool execution output digest; Level 1 witnesses sign the observation subject." },
      { index: 5, kind: "session.end", purpose: "Close certified session and bind final state." }
    ],
    quorum_semantics: "2-of-3 Level 1 witness quorum is over the intent grant and observed execution, not one receipt per witness. 2-of-3 Level 2 policy quorum is collected before the capability grant and attached to intent.grant as typed input evidence."
  };
}

function policyDenialReceiptFlow() {
  return {
    expected_receipt_count: 4,
    side_effect_executed: false,
    note: "Policy-denied attempts receive their own certificate path without an IntentGrant, capability token, tool execution, or observation. This makes denial history auditable without pretending a side effect occurred.",
    steps: [
      { index: 0, kind: "session.start", purpose: "Open certified denial session and bind policy/admission evidence." },
      { index: 1, kind: "policy.request", purpose: "Commit to the attempted email send digest before policy evaluation result is recorded." },
      { index: 2, kind: "policy.decision", purpose: "Attach signed Level 2 policy witness deny decisions and reasons." },
      { index: 3, kind: "session.end", purpose: "Close certified denial session with reason policy_denied." }
    ],
    quorum_semantics: "2-of-3 Level 2 policy witness denial is recorded as signed policy decision evidence. L1 witnesses still sign session boundaries and checkpoint, but no L1 IntentGrant exists because no capability was minted."
  };
}

function policyWitnessSigningSemantics() {
  return {
    version: "strata.email.policy_quorum.v1",
    signing_point: "before intent.grant",
    receipt_attachment_point: "intent.grant.body.intent.intended_action.typed_inputs",
    artifact: "policy-decision.json",
    signed_subject_schema: EMAIL_POLICY_DECISION_VERSION,
    quorum_required: "2-of-3",
    semantics: "Policy witnesses independently sign allow/deny decisions over the exact email payload digest, policy epoch, policy digest, and policy URL. The gateway refuses to mint the side-effect capability unless at least two policy witnesses return allow."
  };
}

export async function runVerifiedEmailSend(input, config, requestContext = {}) {
  if (config.witnesses.length < config.witness.threshold) {
    throw new Error(`email_send_verified requires at least ${config.witness.threshold} Level 1 witness URL(s) in WITNESS_URLS`);
  }
  if (config.policyWitnesses.length < config.policyWitness.threshold) {
    throw new Error(`email_send_verified requires at least ${config.policyWitness.threshold} Level 2 policy witness URL(s) in POLICY_WITNESS_URLS`);
  }

  const runId = `email_${Date.now()}_${randomUUID().slice(0, 8)}`;
  const outDir = join(config.dataDir, "runs", runId);
  const certificateUrl = `${config.certificateBaseUrl}/${runId}`;
  mkdirSync(outDir, { recursive: true });

  const { canonical, publicCommitment } = emailCommitment(input, { from: config.email.from });
  const request = {
    version: "strata.email.send_request.v1",
    email: canonical,
    commitment: publicCommitment,
    certificate_url: certificateUrl
  };

  const paths = artifactPaths(config, outDir);
  const policyBundle = await loadConfiguredPolicyBundle(config);
  const policyUrl = configuredPolicyUrl(config, policyBundle);
  writeJson(paths.policyBundle, policyBundle);
  const policyQuorum = await collectPolicyQuorum({
    witnesses: config.policyWitnesses,
    email: canonical,
    commitment: publicCommitment,
    policyBundle,
    policyUrl,
    threshold: config.policyWitness.threshold
  });
  writeJson(paths.policyDecision, policyQuorum);

  if (!policyQuorum.ok) {
    return createPolicyDeniedCertificate({ config, requestContext, outDir, paths, runId, certificateUrl, request, publicCommitment, policyQuorum, policyBundle, policyUrl });
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
    logId: "email-mcp-transparency-log"
  });
  transparencyLog.reset();

  const egressPolicy = createEgressPolicy(config);
  const policyHash = policyQuorum.policy_bundle_digest;
  const verifierProfile = createVerifierProfile({ profile_id: "profile.email-mcp.l1-l2.v1" });
  const admissionManifest = createSignedEmailAdmissionManifest({ config, requestContext, policyBundle, policyUrl, policyHash, egressPolicy });
  writeJson(paths.admissionManifest, admissionManifest);
  const provider = createEmailProvider(config.email);
  const tool = createEmailTool({ signer: keys.tool.signer, gatewayKeyring: keyring, provider });
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

  await gateway.startSession({ sessionId: `sess_${runId}`, taskInputDigest: publicCommitment.payload_digest });
  const toolResult = await gateway.toolCall({
    toolName: "email-api",
    method: "POST /v1/send-email",
    request,
    inputEdges: [policyQuorumInput(policyQuorum)]
  });
  await gateway.endSession("complete");
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
  const policyBundleVerification = verifyPolicyBundleForQuorum(policyBundle, policyQuorum);
  const ok = session.ok && checkpointResult.ok;
  const registryBinding = await loadAndWriteRegistryBinding(config, paths.registryEpoch);
  const operatorRegistryBinding = await loadAndWriteOperatorRegistryBinding(config, paths.operatorRegistry, admissionManifest);
  const operatorAdmission = verifyOperatorAdmissionManifest(admissionManifest, {
    operatorRegistryBinding,
    requireRegistry: Boolean(config.registry?.url)
  });
  const registryAuthority = registryBinding ? verifyRegistryAuthority({ receipts, checkpoint, keyring, policyQuorum, registryBinding }) : null;
  const verified = ok && policyBundleVerification.ok && operatorAdmission.ok && (!registryAuthority || registryAuthority.ok);
  const verification = { ok: verified, session, checkpoint: checkpointResult, policy_bundle: policyBundleVerification, operator_admission: operatorAdmission, operator_registry: operatorRegistryBinding?.verification || null, registry_authority: registryAuthority };
  writeJson(paths.verification, verification);

  const tinfoilAttestation = await certificateTinfoilEvidence(config, paths);
  const certificateBody = {
    version: "strata.email.certificate.v1",
    run_id: runId,
    certificate_url: certificateUrl,
    bundle_url: `${certificateUrl}/bundle`,
    issued_at: new Date().toISOString(),
    action: {
      mcp_tool_name: "email_send_verified",
      gateway_tool_name: "email-api",
      method: "POST /v1/send-email"
    },
    provider: {
      provider: toolResult.output.provider,
      provider_message_id: toolResult.output.provider_message_id,
      provider_status: toolResult.output.provider_status,
      sent_at: toolResult.output.sent_at
    },
    commitment: publicCommitment,
    admission: operatorAdmissionCertificateBinding(admissionManifest, { operatorRegistryBinding }),
    registry: registryCertificateBinding(registryBinding),
    authority_pins: authorityPins(config, registryBinding, policyBundle),
    tinfoil_attestation: tinfoilAttestation,
    policy: {
      tier: "level-2-policy",
      decision: policyQuorum.decision,
      policy_id: policyQuorum.policy_id,
      policy_epoch_id: policyQuorum.policy_epoch_id,
      policy_bundle_version: policyBundle.version,
      policy_bundle_digest: policyQuorum.policy_bundle_digest,
      policy_url: policyQuorum.policy_url,
      policy_witness_quorum: `${policyQuorum.allow_count}-of-${policyQuorum.total_witnesses}`,
      policy_quorum_threshold: policyQuorum.threshold,
      policy_witness_signing: policyWitnessSigningSemantics()
    },
    proof: {
      assurance_mode: "witnessed",
      witness_tiers: ["level-1-mechanical", "level-2-policy"],
      mechanical_witness_quorum: `${config.witness.threshold}-of-${config.witnesses.length}`,
      policy_witness_quorum: `${policyQuorum.allow_count}-of-${policyQuorum.total_witnesses}`,
      receipt_count: receipts.length,
      checkpoint_id: checkpoint.statement.checkpoint_id,
      receipt_root: session.finalStateRoot,
      verified
    },
    artifacts: {
      ...publicArtifactUrls(config, runId),
      certificate: certificateUrl,
      bundle: `${certificateUrl}/bundle`
    },
    errors: [...session.errors, ...checkpointResult.errors, ...policyBundleVerification.errors, ...operatorAdmission.errors, ...(registryAuthority?.errors || [])]
  };
  const certificateDigest = digestValue(certificateBody);
  const certificate = { ...certificateBody, certificate_digest: certificateDigest };
  writeJson(paths.certificate, certificate);

  return {
    ok: verified,
    run_id: runId,
    out_dir: outDir,
    certificate_ref: certificateUrl,
    certificate_url: certificateUrl,
    bundle_url: `${certificateUrl}/bundle`,
    certificate_digest: certificateDigest,
    tool_output: toolResult.output,
    policy_quorum: policyQuorum,
    policy_bundle: policyBundleMetadata(policyBundle, policyUrl),
    operator_admission: operatorAdmissionCertificateBinding(admissionManifest, { operatorRegistryBinding }),
    registry: registryCertificateBinding(registryBinding),
    registry_authority: registryAuthority,
    policy_witness_signing: policyWitnessSigningSemantics(),
    mechanical_witness_quorum: `${config.witness.threshold}-of-${config.witnesses.length}`,
    certificate_transmission: {
      in_band_headers: toolResult.output.headers_committed,
      header_semantics: {
        "X-Strata-Action-Id": "pre-send IntentGrant grant_id authorizing the exact send",
        "X-Strata-Payload-Digest": "canonical email commitment digest",
        "X-Strata-Certificate-URL": "post-send certificate URL",
        "X-Strata-Witness-Tier": "witness assurance tier"
      },
      recipient_verification_tool: "email_verify_received"
    },
    receipt_flow: emailReceiptFlow(),
    commitment: publicCommitment,
    receipt_count: receipts.length,
    checkpoint_id: checkpoint.statement.checkpoint_id,
    final_state_root: session.finalStateRoot,
    artifacts: {
      ...publicArtifactUrls(config, runId),
      certificate: certificateUrl,
      bundle: `${certificateUrl}/bundle`
    },
    local_artifacts: {
      certificate: paths.certificate,
      receipts: paths.receipts,
      keyring: paths.keyring,
      checkpoint: paths.checkpoint,
      transparency_log: paths.transparencyLog,
      verification: paths.verification,
      admission_manifest: paths.admissionManifest,
      operator_registry: paths.operatorRegistry,
      policy_decision: paths.policyDecision,
      policy_bundle: paths.policyBundle,
      registry_epoch: paths.registryEpoch
    },
    errors: certificate.errors
  };
}

async function createPolicyDeniedCertificate({ config, requestContext, outDir, paths, runId, certificateUrl, request, publicCommitment, policyQuorum, policyBundle, policyUrl }) {
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
    logId: "email-mcp-transparency-log"
  });
  transparencyLog.reset();

  const egressPolicy = createEgressPolicy(config);
  const policyHash = policyQuorum.policy_bundle_digest;
  const verifierProfile = createVerifierProfile({ profile_id: "profile.email-mcp.l1-l2.denial.v1" });
  const admissionManifest = createSignedEmailAdmissionManifest({ config, requestContext, policyBundle, policyUrl, policyHash, egressPolicy });
  writeJson(paths.admissionManifest, admissionManifest);
  const gateway = new ActionGateway({
    log,
    signer: keys.gateway.signer,
    tools: {},
    policyHash,
    verifierProfile,
    admissionManifest,
    witnesses,
    sideEffectWitnessThreshold: 0,
    sessionBoundaryWitnessThreshold: config.witness.threshold,
    checkpointWitnessThreshold: config.witness.threshold,
    transparencyLog
  });

  await gateway.startSession({ sessionId: `sess_${runId}`, taskInputDigest: publicCommitment.payload_digest });
  const stepIndex = gateway.nextStep();
  const requestDigest = toolRequestDigest({
    toolAudience: "email-api",
    method: "POST /v1/send-email",
    request
  });
  const policyRequestReceipt = await gateway.appendGatewayReceipt("policy.request", {
    action_type: "tool.call",
    tool_audience: "email-api",
    method: "POST /v1/send-email",
    request_digest: requestDigest,
    email_payload_digest: publicCommitment.payload_digest,
    commitment: publicCommitment
  }, { stepIndex });
  const policyQuorumDigest = digestValue(policyQuorum);
  await gateway.appendGatewayReceipt("policy.decision", {
    request_receipt_root: policyRequestReceipt.state_root,
    decision: "deny",
    denial_stage: "level-2-policy",
    policy_quorum_digest: policyQuorumDigest,
    policy_quorum: policyQuorum,
    deny_reasons: policyQuorum.deny_reasons,
    output_digest: policyQuorumDigest
  }, { stepIndex });
  await gateway.endSession("policy_denied");
  const checkpoint = await gateway.createCheckpoint({ checkpointId: `chk_${runId}` });
  writeCheckpoint(paths.checkpoint, checkpoint);

  const receipts = log.readAll();
  const transparencyLogEntries = transparencyLog.readAll();
  const session = verifySession(receipts, keyring, {
    transparencyLogEntries,
    requireAdmissionManifest: true,
    requireBoundaryQuorum: true,
    requireTransparencyLog: true
  });
  const checkpointResult = verifyCheckpoint(checkpoint, receipts, keyring, {
    transparencyLogEntries,
    requireCheckpointQuorum: true,
    requireCheckpointTransparency: true
  });
  const policyBundleVerification = verifyPolicyBundleForQuorum(policyBundle, policyQuorum);
  const ok = session.ok && checkpointResult.ok && policyBundleVerification.ok && policyQuorum.decision === "deny";
  const registryBinding = await loadAndWriteRegistryBinding(config, paths.registryEpoch);
  const operatorRegistryBinding = await loadAndWriteOperatorRegistryBinding(config, paths.operatorRegistry, admissionManifest);
  const operatorAdmission = verifyOperatorAdmissionManifest(admissionManifest, {
    operatorRegistryBinding,
    requireRegistry: Boolean(config.registry?.url)
  });
  const registryAuthority = registryBinding ? verifyRegistryAuthority({ receipts, checkpoint, keyring, policyQuorum, registryBinding }) : null;
  const verified = ok && operatorAdmission.ok && (!registryAuthority || registryAuthority.ok);
  const verification = { ok: verified, session, checkpoint: checkpointResult, policy_bundle: policyBundleVerification, operator_admission: operatorAdmission, operator_registry: operatorRegistryBinding?.verification || null, policy_denial: { ok: policyQuorum.decision === "deny", policy_quorum: policyQuorum }, registry_authority: registryAuthority };
  writeJson(paths.verification, verification);

  const tinfoilAttestation = await certificateTinfoilEvidence(config, paths);
  const certificateBody = {
    version: "strata.email.policy_denial_certificate.v1",
    run_id: runId,
    certificate_url: certificateUrl,
    bundle_url: `${certificateUrl}/bundle`,
    issued_at: new Date().toISOString(),
    denied: true,
    denial_stage: "level-2-policy",
    action: {
      mcp_tool_name: "email_send_verified",
      gateway_tool_name: "email-api",
      method: "POST /v1/send-email"
    },
    commitment: publicCommitment,
    admission: operatorAdmissionCertificateBinding(admissionManifest, { operatorRegistryBinding }),
    registry: registryCertificateBinding(registryBinding),
    authority_pins: authorityPins(config, registryBinding, policyBundle),
    tinfoil_attestation: tinfoilAttestation,
    policy: {
      tier: "level-2-policy",
      decision: policyQuorum.decision,
      deny_reasons: policyQuorum.deny_reasons,
      policy_id: policyQuorum.policy_id,
      policy_epoch_id: policyQuorum.policy_epoch_id,
      policy_bundle_version: policyBundle.version,
      policy_bundle_digest: policyQuorum.policy_bundle_digest,
      policy_url: policyQuorum.policy_url,
      policy_witness_quorum: `${policyQuorum.allow_count}-of-${policyQuorum.total_witnesses}`,
      policy_quorum_threshold: policyQuorum.threshold,
      policy_witness_signing: policyWitnessSigningSemantics()
    },
    proof: {
      assurance_mode: "policy_denied",
      witness_tiers: ["level-1-mechanical", "level-2-policy"],
      mechanical_boundary_quorum: `${config.witness.threshold}-of-${config.witnesses.length}`,
      policy_witness_quorum: `${policyQuorum.allow_count}-of-${policyQuorum.total_witnesses}`,
      receipt_count: receipts.length,
      checkpoint_id: checkpoint.statement.checkpoint_id,
      receipt_root: session.finalStateRoot,
      side_effect_executed: false,
      verified
    },
    denial_receipt_flow: policyDenialReceiptFlow(),
    artifacts: {
      ...publicArtifactUrls(config, runId),
      certificate: certificateUrl,
      bundle: `${certificateUrl}/bundle`
    },
    errors: [...session.errors, ...checkpointResult.errors, ...policyBundleVerification.errors, ...operatorAdmission.errors, ...(registryAuthority?.errors || [])]
  };
  const certificateDigest = digestValue(certificateBody);
  const certificate = { ...certificateBody, certificate_digest: certificateDigest };
  writeJson(paths.certificate, certificate);

  return {
    ok: false,
    denied: true,
    denial_stage: "level-2-policy",
    run_id: runId,
    out_dir: outDir,
    policy_quorum: policyQuorum,
    policy_bundle: policyBundleMetadata(policyBundle, policyQuorum.policy_url),
    operator_admission: operatorAdmissionCertificateBinding(admissionManifest, { operatorRegistryBinding }),
    registry: registryCertificateBinding(registryBinding),
    registry_authority: registryAuthority,
    policy_witness_signing: policyWitnessSigningSemantics(),
    mechanical_witness_quorum: `${config.witness.threshold}-of-${config.witnesses.length}`,
    commitment: publicCommitment,
    certificate_ref: certificateUrl,
    certificate_url: certificateUrl,
    bundle_url: `${certificateUrl}/bundle`,
    certificate_digest: certificateDigest,
    tool_output: null,
    receipt_count: receipts.length,
    checkpoint_id: checkpoint.statement.checkpoint_id,
    final_state_root: session.finalStateRoot,
    denial_receipt_flow: policyDenialReceiptFlow(),
    artifacts: {
      ...publicArtifactUrls(config, runId),
      certificate: certificateUrl,
      bundle: `${certificateUrl}/bundle`
    },
    local_artifacts: {
      certificate: paths.certificate,
      receipts: paths.receipts,
      keyring: paths.keyring,
      checkpoint: paths.checkpoint,
      transparency_log: paths.transparencyLog,
      verification: paths.verification,
      admission_manifest: paths.admissionManifest,
      operator_registry: paths.operatorRegistry,
      policy_decision: paths.policyDecision,
      policy_bundle: paths.policyBundle,
      registry_epoch: paths.registryEpoch
    },
    errors: [`L2 policy denied email send: ${policyQuorum.deny_reasons.join(", ") || "policy quorum not met"}`]
  };
}

export function verifyReceivedEmail(input, config) {
  const certificatePath = resolveCertificatePath(input.certificate_ref, config);
  const certificate = JSON.parse(readFileSync(certificatePath, "utf8"));
  const received = parseMaybeJsonObject(input.received, "received");
  const { publicCommitment } = emailCommitment(received, { from: config.email.from }, {
    commitmentVersion: certificate.commitment?.version
  });
  const receivedHeaders = normalizeHeaders(received.headers);
  const headerVerification = verifyStrataHeaders(receivedHeaders, certificate, input.certificate_ref);
  const contentMatch = publicCommitment.payload_digest === certificate.commitment.payload_digest;
  const artifacts = resolveArtifacts(certificate.artifacts, config);
  const receipts = readJsonl(artifacts.receipts);
  const keyring = JSON.parse(readFileSync(artifacts.keyring, "utf8"));
  const checkpoint = JSON.parse(readFileSync(artifacts.checkpoint, "utf8"));
  const admissionManifest = artifacts.admission_manifest && existsSync(artifacts.admission_manifest)
    ? JSON.parse(readFileSync(artifacts.admission_manifest, "utf8"))
    : null;
  const operatorRegistryBinding = artifacts.operator_registry && existsSync(artifacts.operator_registry)
    ? JSON.parse(readFileSync(artifacts.operator_registry, "utf8"))
    : null;
  const operatorAdmissionVerification = optionalOperatorAdmissionVerification(admissionManifest, {
    required: Boolean(certificate.admission),
    operatorRegistryBinding,
    requireRegistry: Boolean(certificate.admission?.operator_registry_url)
  });
  const operatorAdmissionCertificateErrors = operatorAdmissionCertificateBindingErrors(certificate, operatorAdmissionVerification);
  const policyBundle = artifacts.policy_bundle && existsSync(artifacts.policy_bundle)
    ? JSON.parse(readFileSync(artifacts.policy_bundle, "utf8"))
    : null;
  const policyDecision = artifacts.policy_decision && existsSync(artifacts.policy_decision)
    ? JSON.parse(readFileSync(artifacts.policy_decision, "utf8"))
    : null;
  const policyBundleVerification = verifyPolicyBundleForQuorum(policyBundle, policyDecision || {
    policy_bundle_digest: certificate.policy?.policy_bundle_digest,
    policy_epoch_id: certificate.policy?.policy_epoch_id,
    policy_url: certificate.policy?.policy_url,
    decisions: []
  });
  const transparencyLogEntries = readJsonl(artifacts.transparency_log);
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
  const certificateVerified = session.ok && checkpointResult.ok && operatorAdmissionVerification.ok && operatorAdmissionCertificateErrors.length === 0 && policyBundleVerification.ok && digestValue(withoutDigest(certificate)) === certificate.certificate_digest;
  const result = contentMatch && certificateVerified ? "valid" : "invalid";
  const verifierKey = loadRecipientVerifierKey(config);
  const unsigned = {
    version: "strata.recipient.verification_receipt.v1",
    receipt_id: `rv_${Date.now()}_${randomUUID().slice(0, 8)}`,
    result,
    verified_at: new Date().toISOString(),
    verifier: {
      key_id: verifierKey.signer.keyId,
      public_key_pem: verifierKey.publicKeyPem
    },
    certificate_digest: certificate.certificate_digest,
    certificate_ref: input.certificate_ref,
    provider_message_id: certificate.provider.provider_message_id,
    expected_payload_digest: certificate.commitment.payload_digest,
    received_payload_digest: publicCommitment.payload_digest,
    received_headers_present: Object.keys(receivedHeaders).length > 0,
    header_verification: headerVerification,
    operator_admission_verification: operatorAdmissionVerification,
    policy_bundle_verification: policyBundleVerification,
    content_match: contentMatch,
    certificate_verified: certificateVerified,
    verification_errors: [
      ...session.errors.map((error) => `session: ${error}`),
      ...checkpointResult.errors.map((error) => `checkpoint: ${error}`),
      ...operatorAdmissionVerification.errors.map((error) => `operator admission: ${error}`),
      ...operatorAdmissionCertificateErrors.map((error) => `operator admission: ${error}`),
      ...policyBundleVerification.errors.map((error) => `policy bundle: ${error}`)
    ]
  };
  const receipt = {
    ...unsigned,
    signature: signEd25519(canonicalize(unsigned), verifierKey.signer.privateKey)
  };
  const outDir = join(config.dataDir, "recipient-verifications");
  mkdirSync(outDir, { recursive: true });
  const receiptPath = join(outDir, `${receipt.receipt_id}.json`);
  writeJson(receiptPath, receipt);
  return { receipt, receipt_path: receiptPath };
}

function emailInputSchema() {
  return {
    type: "object",
    properties: {
      from: { type: "string", description: "Optional sender address. Defaults to EMAIL_FROM." },
      to: { type: "array", items: { type: "string" }, description: "Recipient email addresses" },
      cc: { type: "array", items: { type: "string" } },
      bcc: { type: "array", items: { type: "string" } },
      reply_to: { type: "array", items: { type: "string" } },
      subject: { type: "string" },
      text: { type: "string" },
      html: { type: "string" },
      tags: { type: "object", additionalProperties: { type: "string" } },
      attachments: {
        type: "array",
        items: {
          type: "object",
          properties: {
            filename: { type: "string" },
            content_type: { type: "string" },
            content_base64: { type: "string" }
          },
          required: ["filename", "content_base64"],
          additionalProperties: false
        }
      }
    },
    required: ["to", "subject"],
    additionalProperties: false
  };
}

function emailReceivedInputSchema() {
  const schema = emailInputSchema();
  return {
    ...schema,
    properties: {
      ...schema.properties,
      headers: {
        type: "object",
        description: "Optional received message headers. Include X-Strata-* headers if available from the mail API/client.",
        additionalProperties: { type: "string" },
        properties: {
          "X-Strata-Action-Id": { type: "string" },
          "X-Strata-Payload-Digest": { type: "string" },
          "X-Strata-Certificate-URL": { type: "string" },
          "X-Strata-Witness-Tier": { type: "string" }
        }
      }
    }
  };
}

function parseMaybeJsonObject(value, fieldName) {
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch (error) {
      throw new Error(`${fieldName} must be an object or JSON object string: ${error.message}`);
    }
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  return value;
}

function normalizeHeaders(headers) {
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) {
    return {};
  }
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), String(value)]));
}

function verifyStrataHeaders(headers, certificate, certificateRef) {
  const expected = {
    "x-strata-payload-digest": certificate.commitment.payload_digest,
    "x-strata-certificate-url": certificate.certificate_url,
    "x-strata-witness-tier": certificate.proof?.witness_tier || (certificate.proof?.witness_tiers || []).find((tier) => tier === "level-1-mechanical") || "level-1-mechanical"
  };
  const checks = Object.fromEntries(Object.entries(expected).map(([key, value]) => {
    const actual = headers[key] || null;
    return [key, {
      present: Boolean(actual),
      expected: value,
      actual,
      match: actual ? actual === value : null
    }];
  }));
  checks["x-strata-action-id"] = {
    present: Boolean(headers["x-strata-action-id"]),
    expected_prefix: "grant_",
    actual: headers["x-strata-action-id"] || null,
    match: headers["x-strata-action-id"] ? headers["x-strata-action-id"].startsWith("grant_") : null
  };
  return {
    supplied: Object.keys(headers).length > 0,
    note: "Headers are optional because some mail APIs hide custom headers. When supplied, X-Strata-* headers are checked against the certificate metadata.",
    certificate_ref_provided: certificateRef,
    certificate_ref_matches_header_or_url: headers["x-strata-certificate-url"] ? headers["x-strata-certificate-url"] === certificate.certificate_url : null,
    checks
  };
}

function artifactPaths(config, outDir) {
  return {
    receipts: join(outDir, "receipts.jsonl"),
    keyring: join(outDir, "keyring.json"),
    checkpoint: join(outDir, "checkpoint.json"),
    transparencyLog: join(outDir, "transparency-log.jsonl"),
    verification: join(outDir, "verification.json"),
    certificate: join(outDir, "certificate.json"),
    admissionManifest: join(outDir, "admission-manifest.json"),
    operatorRegistry: join(outDir, "operator-registry.json"),
    policyDecision: join(outDir, "policy-decision.json"),
    policyBundle: join(outDir, "policy-bundle.json"),
    registryEpoch: join(outDir, "registry-epoch.json"),
    gatewayAttestation: join(outDir, "gateway-attestation.json"),
    l1WitnessAttestations: join(outDir, "l1-witness-attestations.json")
  };
}

function publicArtifactUrls(config, runId) {
  const baseUrl = `${config.certificateBaseUrl}/${runId}/artifacts`;
  return {
    receipts: `${baseUrl}/receipts.jsonl`,
    keyring: `${baseUrl}/keyring.json`,
    checkpoint: `${baseUrl}/checkpoint.json`,
    transparency_log: `${baseUrl}/transparency-log.jsonl`,
    verification: `${baseUrl}/verification.json`,
    admission_manifest: `${baseUrl}/admission-manifest.json`,
    operator_registry: `${baseUrl}/operator-registry.json`,
    policy_decision: `${baseUrl}/policy-decision.json`,
    policy_bundle: `${baseUrl}/policy-bundle.json`,
    registry_epoch: `${baseUrl}/registry-epoch.json`,
    gateway_attestation: `${baseUrl}/gateway-attestation.json`,
    l1_witness_attestations: `${baseUrl}/l1-witness-attestations.json`
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
    tool: loadOrCreateEd25519Signer({ keyFile: join(keyDir, "email-tool.key.json"), keyId: "tool:email-api:email-mcp" }),
    transparency: loadOrCreateEd25519Signer({ keyFile: join(keyDir, "transparency.key.json"), keyId: "transparency:email-mcp" })
  };
}

function loadRecipientVerifierKey(config) {
  const keyDir = join(config.dataDir, "keys");
  mkdirSync(keyDir, { recursive: true });
  return loadOrCreateEd25519Signer({ keyFile: join(keyDir, "recipient-verifier.key.json"), keyId: "recipient-verifier:email-mcp" });
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
      witnessEpochId: spec.witnessEpochId ?? config.witness.signedRequests.witnessEpochId,
      registryEpochId: spec.registryEpochId ?? config.witness.signedRequests.registryEpochId,
      workflowId: spec.workflowId ?? config.witness.signedRequests.workflowId
    } : null
  }));
  for (const witness of witnesses) {
    const publicKey = await witness.publicKey();
    keyring[publicKey.key_id] = publicKey.public_key_pem;
  }
  return witnesses;
}

async function checkWitness(spec) {
  try {
    const [healthResponse, keyResponse] = await Promise.all([
      fetch(`${spec.url.replace(/\/$/, "")}/health`),
      fetch(`${spec.url.replace(/\/$/, "")}/v1/public-key`)
    ]);
    const health = await healthResponse.json();
    const publicKey = await keyResponse.json();
    return {
      id: spec.id,
      url: spec.url,
      ok: healthResponse.ok && keyResponse.ok && Boolean(publicKey.key_id),
      health,
      key_id: publicKey.key_id || null
    };
  } catch (error) {
    return {
      id: spec.id,
      url: spec.url,
      ok: false,
      error: error.message
    };
  }
}

async function checkPolicyWitness(spec) {
  try {
    const baseUrl = spec.url.replace(/\/$/, "");
    const [healthResponse, keyResponse, policyResponse] = await Promise.all([
      fetch(`${baseUrl}/health`),
      fetch(`${baseUrl}/v1/public-key`),
      fetch(`${baseUrl}/v1/policy`)
    ]);
    const health = await healthResponse.json();
    const publicKey = await keyResponse.json();
    const policy = await policyResponse.json();
    return {
      id: spec.id,
      url: spec.url,
      ok: healthResponse.ok && keyResponse.ok && policyResponse.ok && Boolean(publicKey.key_id) && Boolean(policy.policy_bundle_digest),
      health,
      key_id: publicKey.key_id || null,
      policy_bundle_digest: policy.policy_bundle_digest || null,
      policy_epoch_id: policy.policy_bundle?.epoch_id || null,
      policy_url: policy.policy_url || null
    };
  } catch (error) {
    return {
      id: spec.id,
      url: spec.url,
      ok: false,
      error: error.message
    };
  }
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
    policy_url: policyQuorum.policy_url,
    threshold: policyQuorum.threshold,
    allow_count: policyQuorum.allow_count,
    deny_count: policyQuorum.deny_count,
    total_witnesses: policyQuorum.total_witnesses,
    decision_digests: policyQuorum.decisions.map((decision) => digestValue({
      subject: decision.subject,
      signature: decision.signature
    }))
  };
}

async function loadAndWriteRegistryBinding(config, registryEpochPath) {
  if (!config.registry?.url) {
    return null;
  }
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
  if (!config.registry?.url || !admissionManifest?.operator_signature?.operator_id) {
    return null;
  }
  const binding = await fetchOperatorRegistryBinding(config.registry.url, admissionManifest.operator_signature.operator_id, registryPinOptions(config));
  writeJson(operatorRegistryPath, binding);
  return binding;
}

function registryCertificateBinding(registryBinding) {
  if (!registryBinding) {
    return null;
  }
  return {
    registry_epoch_id: registryBinding.epoch.epoch_id,
    registry_epoch_digest: registryBinding.epoch_digest,
    registry_epoch_url: registryBinding.epoch_url,
    registry_authority_key_id: registryBinding.trust_anchor.key_id,
    policy_bundle_digest: registryBinding.epoch.policy_bundle_digest,
    policy_bundle_url: registryBinding.epoch.policy_bundle_url || null,
    pinned: registryBinding.pinned || null
  };
}

function registryPinOptions(config) {
  return {
    expectedEpochDigest: config.registry?.expectedEpochDigest || "",
    trustAnchorKeyId: config.registry?.trustAnchorKeyId || "",
    trustAnchorPublicKeyPem: config.registry?.trustAnchorPublicKeyPem || ""
  };
}

function authorityPins(config, registryBinding, policyBundle) {
  const policyDigest = policyBundle ? policyBundleDigest(policyBundle) : null;
  return {
    registry_epoch: {
      expected_digest: config.registry?.expectedEpochDigest || null,
      actual_digest: registryBinding?.epoch_digest || null,
      pinned: Boolean(config.registry?.expectedEpochDigest),
      matched: config.registry?.expectedEpochDigest ? config.registry.expectedEpochDigest === registryBinding?.epoch_digest : null
    },
    registry_trust_anchor: {
      expected_key_id: config.registry?.trustAnchorKeyId || null,
      actual_key_id: registryBinding?.trust_anchor?.key_id || null,
      pinned: Boolean(config.registry?.trustAnchorKeyId && config.registry?.trustAnchorPublicKeyPem),
      matched: config.registry?.trustAnchorKeyId ? config.registry.trustAnchorKeyId === registryBinding?.trust_anchor?.key_id : null
    },
    policy_bundle: {
      expected_digest: config.policy?.expectedDigest || null,
      actual_digest: policyDigest,
      pinned: Boolean(config.policy?.expectedDigest),
      matched: config.policy?.expectedDigest ? config.policy.expectedDigest === policyDigest : null
    }
  };
}

function assertExpectedDigest(label, actual, expected) {
  if (expected && actual !== expected) {
    throw new Error(`${label} digest mismatch: expected=${expected} actual=${actual}`);
  }
}

function verifyRegistryAuthority({ receipts, checkpoint, keyring, policyQuorum, registryBinding }) {
  const trustAnchors = { [registryBinding.trust_anchor.key_id]: registryBinding.trust_anchor.public_key_pem };
  const l1Mechanical = verifyWitnessAuthority({
    receipts,
    checkpoint,
    keyring,
    registryEpoch: registryBinding.epoch,
    trustAnchors,
    workflowId: "email.send",
    policyHash: policyQuorum.policy_bundle_digest,
    requiredTier: "mechanical"
  });
  const l2Policy = verifyPolicyQuorumAuthority({
    policyQuorum,
    registryEpoch: registryBinding.epoch,
    workflowId: "email.send",
    policyHash: policyQuorum.policy_bundle_digest,
    requiredTier: "policy"
  });
  const errors = [
    ...registryBinding.verification.errors.map((error) => `registry epoch: ${error}`),
    ...l1Mechanical.errors.map((error) => `l1 mechanical: ${error}`),
    ...l2Policy.errors.map((error) => `l2 policy: ${error}`)
  ];
  return {
    ok: errors.length === 0,
    errors,
    registry_epoch_digest: registryBinding.epoch_digest,
    registry_epoch_id: registryBinding.epoch.epoch_id,
    registry_epoch_url: registryBinding.epoch_url,
    registry_authority_key_id: registryBinding.trust_anchor.key_id,
    l1_mechanical: l1Mechanical,
    l2_policy: l2Policy
  };
}

function createSignedEmailAdmissionManifest({ config, requestContext, policyBundle, policyUrl, policyHash, egressPolicy }) {
  const tenantId = requestContext?.session?.tid || config.tenant.id;
  const operatorSigner = loadOperatorAdmissionSigner(config);
  const unsignedManifest = {
    ...createAdmissionManifest({
      manifestId: `adm_email_mcp_${tenantId}_v1`,
      governanceId: "gov_email_mcp_v1",
      policyHash,
      agent: tinfoilEvidence(null, "mcp-agent", ["mcp://tools/*"], null),
      gateway: tinfoilEvidence(config.attestation?.gateway, "email-gateway", ["strata://verified-actions/email.send"], egressPolicy),
      verifier: tinfoilEvidence(null, "email-verifier", ["verify://local/email"], null),
      approvedTools: [{ tool_id: "email-api", audience: "email-api", methods: ["POST /v1/send-email"] }],
      approvedDataSources: [],
      approvedModels: [],
      witnessSetId: "witness-set.email-mcp.l1+l2",
      witnessThreshold: config.witness.threshold
    }),
    tenant_id: tenantId,
    operator_id: config.operator.id,
    policy_bundle_url: policyUrl || null,
    active_policy: policyBundleMetadata(policyBundle, policyUrl),
    auth_context: admissionAuthContext(requestContext, tenantId)
  };
  return attachOperatorSignature(unsignedManifest, {
    signer: operatorSigner.signer,
    publicKeyPem: operatorSigner.publicKeyPem,
    operatorId: config.operator.id,
    tenantId
  });
}

function admissionAuthContext(requestContext, tenantId) {
  const session = requestContext?.session;
  if (!session) {
    return { auth_method: "none", tenant_id: tenantId };
  }
  return {
    auth_method: session.auth_method || "mcp-session",
    tenant_id: session.tid || tenantId,
    client_id: session.aid || null,
    scope: session.scope || null
  };
}

async function loadConfiguredPolicyBundle(config) {
  const policyBundle = await loadEmailPolicyBundle({
    file: config.policy?.bundleFile,
    url: config.policy?.bundleUrl || ""
  });
  assertExpectedDigest("policy bundle", policyBundleDigest(policyBundle), config.policy?.expectedDigest);
  return policyBundle;
}

function configuredPolicyUrl(config, policyBundle) {
  if (config.policy?.bundleUrl) {
    return config.policy.bundleUrl;
  }
  if (config.registry?.url) {
    return `${config.registry.url}/policies/epochs/${policyBundle.epoch_id}`;
  }
  return "";
}

function verifyPolicyBundleForQuorum(policyBundle, policyQuorum) {
  const errors = [];
  if (!policyBundle) {
    errors.push("policy bundle artifact missing");
  }
  const policyBundleDigestValue = policyBundle ? policyBundleDigest(policyBundle) : null;
  if (policyBundleDigestValue !== policyQuorum.policy_bundle_digest) {
    errors.push(`policy bundle digest mismatch: bundle=${policyBundleDigestValue} quorum=${policyQuorum.policy_bundle_digest}`);
  }
  if (policyBundle?.epoch_id !== policyQuorum.policy_epoch_id) {
    errors.push(`policy epoch mismatch: bundle=${policyBundle?.epoch_id} quorum=${policyQuorum.policy_epoch_id}`);
  }
  const decisionMismatches = (policyQuorum.decisions || [])
    .filter((decision) => decision.subject?.policy_bundle_digest !== policyQuorum.policy_bundle_digest)
    .map((decision) => decision.signature?.key_id || decision.key_id || decision.witness_id);
  if (decisionMismatches.length > 0) {
    errors.push(`policy decision digest mismatch for keys: ${decisionMismatches.join(", ")}`);
  }
  return {
    ok: errors.length === 0,
    errors,
    policy_id: policyBundle?.policy_id || null,
    policy_epoch_id: policyBundle?.epoch_id || null,
    policy_bundle_digest: policyBundleDigestValue,
    policy_url: policyQuorum.policy_url || null
  };
}

function operatorAdmissionCertificateBindingErrors(certificate, verification) {
  if (!certificate.admission) {
    return [];
  }
  const errors = [];
  if (verification.signed_manifest_digest !== certificate.admission.admission_manifest_digest) {
    errors.push("admission manifest digest does not match certificate admission binding");
  }
  if (verification.operator_key_id !== certificate.admission.operator_key_id) {
    errors.push("operator key does not match certificate admission binding");
  }
  if (verification.tenant_id !== certificate.admission.tenant_id) {
    errors.push("tenant does not match certificate admission binding");
  }
  if (certificate.admission.operator_registry_url && verification.operator_registry_url !== certificate.admission.operator_registry_url) {
    errors.push("operator registry URL does not match certificate admission binding");
  }
  if (certificate.admission.operator_registry_record_digest && verification.operator_registry_record_digest !== certificate.admission.operator_registry_record_digest) {
    errors.push("operator registry record digest does not match certificate admission binding");
  }
  return errors;
}

async function safeRegistryStatus(config) {
  if (!config.registry?.url) {
    return { configured: false };
  }
  try {
    const binding = await fetchRegistryBinding(config.registry.url, registryPinOptions(config));
    return {
      configured: true,
      ok: binding.verification.ok,
      registry_epoch_id: binding.epoch.epoch_id,
      registry_epoch_digest: binding.epoch_digest,
      registry_epoch_url: binding.epoch_url,
      registry_authority_key_id: binding.trust_anchor.key_id,
      policy_bundle_digest: binding.epoch.policy_bundle_digest,
      policy_bundle_url: binding.epoch.policy_bundle_url || null,
      pinned: binding.pinned,
      errors: binding.verification.errors
    };
  } catch (error) {
    return { configured: true, ok: false, error: error.message };
  }
}

function createEgressPolicy(config) {
  const allowedUrls = [...config.witnesses, ...config.policyWitnesses].map((witness) => witness.url);
  if (config.registry?.url) {
    allowedUrls.push(config.registry.url);
  }
  if (config.policy?.bundleUrl) {
    allowedUrls.push(config.policy.bundleUrl);
  }
  if (config.email.provider === "resend") {
    allowedUrls.push(config.email.resendBaseUrl);
  }
  if (config.attestation?.gateway?.attestationUrl) {
    allowedUrls.push(config.attestation.gateway.attestationUrl);
  }
  for (const witness of config.attestation?.l1Witnesses || []) {
    if (witness.attestationUrl) {
      allowedUrls.push(witness.attestationUrl);
    }
  }
  return {
    mode: "email-provider-l1-and-l2-witness-urls-only",
    allowed_urls: allowedUrls.sort(),
    enforcement: "application-code-typed-adapters",
    evidence_ref: "runtime env WITNESS_URLS + POLICY_WITNESS_URLS + EMAIL_PROVIDER",
    note: "Functional L1/L2 demo policy evidence, not a TEE-native network firewall proof."
  };
}

async function certificateTinfoilEvidence(config, paths = null) {
  const gatewayObserved = await measuredRuntimeSummary(config.attestation?.gateway);
  const l1Observed = (await Promise.all((config.attestation?.l1Witnesses || []).map(measuredRuntimeSummary))).filter(Boolean);
  const gateway = gatewayObserved?.summary || null;
  const l1Witnesses = l1Observed.map((item) => item.summary).filter(Boolean);
  if (!gateway && l1Witnesses.length === 0) {
    return null;
  }
  writeTinfoilAttestationArtifacts(paths, gatewayObserved, l1Observed);
  return {
    version: "strata.tinfoil_attestation_binding.v1",
    gateway,
    l1_witnesses: l1Witnesses,
    note: "These are verifier-facing bindings to Tinfoil measurement evidence for the runtimes used by this certificate. Verifiers should independently verify the referenced Tinfoil attestation against the public config repos and tags."
  };
}

async function measuredRuntimeSummary(evidence) {
  if (!evidence || (!evidence.attestationDigest && !evidence.configRepo && !evidence.configTag)) {
    return null;
  }
  const observedAttestation = await fetchObservedTinfoilAttestation(evidence);
  return {
    document: observedAttestation?.document || null,
    attestationBundle: observedAttestation?.attestationBundle || null,
    summary: {
    platform: "tinfoil-containers",
    witness_id: evidence.witnessId || null,
    container_name: evidence.containerName || null,
    config_repo: evidence.configRepo || null,
    config_tag: evidence.configTag || null,
    image_digest: evidence.imageDigest || null,
    attestation_digest: evidence.attestationDigest || observedAttestation?.summary?.attestation_document_digest || null,
    attestation_ref: evidence.attestationRef || evidence.attestationUrl || tinfoilReleaseRef(evidence),
    sigstore_bundle_ref: evidence.sigstoreBundleRef || tinfoilReleaseRef(evidence),
    observed_attestation: observedAttestation?.summary || null,
    debug_mode: false
    }
  };
}

function writeTinfoilAttestationArtifacts(paths, gatewayObserved, l1Observed) {
  if (!paths) {
    return;
  }
  if (gatewayObserved?.document) {
    writeJson(paths.gatewayAttestation, {
      version: "strata.tinfoil_observed_attestation.v1",
      runtime: gatewayObserved.summary,
      document: gatewayObserved.document,
      attestation_bundle: gatewayObserved.attestationBundle || null
    });
  }
  const l1Documents = l1Observed.filter((item) => item.document).map((item) => ({
    runtime: item.summary,
    document: item.document,
    attestation_bundle: item.attestationBundle || null
  }));
  if (l1Documents.length > 0) {
    writeJson(paths.l1WitnessAttestations, {
      version: "strata.tinfoil_observed_l1_attestations.v1",
      witnesses: l1Documents
    });
  }
}

function tinfoilEvidence(evidence, containerName, shimPaths, egressPolicy) {
  return createTinfoilEvidence({
    containerName: evidence?.containerName || containerName,
    imageDigest: evidence?.imageDigest || `sha256:${sha256Hex(`email-mcp:${containerName}`)}`,
    configHash: evidence?.attestationDigest || sha256Hex(`email-mcp-config:${containerName}`),
    attestationRef: evidence?.attestationRef || evidence?.attestationUrl || `demo://email-mcp/${containerName}/attestation-placeholder`,
    sigstoreBundleRef: evidence?.sigstoreBundleRef || tinfoilReleaseRef(evidence) || `sigstore://email-mcp/${containerName}`,
    shimPaths,
    egressPolicy
  });
}

async function fetchObservedTinfoilAttestation(evidence) {
  if (!evidence?.attestationUrl) {
    return null;
  }
  const observedAt = new Date().toISOString();
  try {
    const attestationBundle = evidence.configRepo
      ? await assembleObservedAttestationBundle(evidence)
      : null;
    const document = attestationBundle?.enclaveAttestationReport || await fetchAttestationDocument(evidence.attestationUrl);
    if (!document.format || !document.body) {
      throw new Error("attestation document must include format and body");
    }
    const tinfoilDocumentHash = await hashAttestationDocument(document);
    return {
      document,
      attestationBundle,
      summary: {
      status: "ok",
      observed_at: observedAt,
      source_url: evidence.attestationUrl,
      format: document.format,
      attestation_document_digest: digestValue(document),
      tinfoil_document_hash: tinfoilDocumentHash,
      body_digest: sha256Hex(document.body),
      body_length: document.body.length,
      release_digest: attestationBundle?.digest || null,
      has_sigstore_bundle: Boolean(attestationBundle?.sigstoreBundle),
      has_vcek: Boolean(attestationBundle?.vcek),
      has_enclave_cert: Boolean(attestationBundle?.enclaveCert),
      digest_semantics: "attestation_document_digest is sha256 over Strata canonical JSON for the Tinfoil /.well-known/tinfoil-attestation document; tinfoil_document_hash is the official Tinfoil hashAttestationDocument(format + body) value used for certificate SAN verification"
      }
    };
  } catch (error) {
    if (evidence.attestationRequired) {
      throw error;
    }
    return {
      document: null,
      summary: {
      status: "error",
      observed_at: observedAt,
      source_url: evidence.attestationUrl,
      error: error.message
      }
    };
  }
}

async function assembleObservedAttestationBundle(evidence) {
  const enclaveHost = new URL(evidence.attestationUrl).hostname;
  const bundle = await assembleAttestationBundle(enclaveHost, evidence.configRepo);
  if (bundle.enclaveAttestationReport?.format && bundle.enclaveAttestationReport?.body) {
    return bundle;
  }
  throw new Error("assembled Tinfoil attestation bundle is missing enclave attestation report");
}

async function fetchAttestationDocument(url) {
  const response = await fetch(url, { headers: { accept: "application/json" } });
  const text = await response.text();
  let document;
  try {
    document = JSON.parse(text);
  } catch (error) {
    throw new Error(`attestation response was not JSON: ${error.message}`);
  }
  if (!response.ok) {
    throw new Error(document.error || `attestation endpoint returned ${response.status}`);
  }
  return document;
}

function tinfoilReleaseRef(evidence) {
  if (!evidence?.configRepo || !evidence?.configTag) {
    return null;
  }
  return `https://github.com/${evidence.configRepo}/releases/tag/${evidence.configTag}`;
}

function resolveCertificatePath(ref, config) {
  if (!ref) {
    throw new Error("certificate_ref is required");
  }
  let path;
  if (ref.startsWith("file://")) {
    path = fileURLToPath(ref);
  } else if (ref.startsWith(config.certificateBaseUrl)) {
    const runId = ref.slice(config.certificateBaseUrl.length).replace(/^\//, "").split("/")[0];
    path = join(config.dataDir, "runs", runId);
  } else {
    path = ref;
  }
  if (existsSync(join(path, "certificate.json"))) {
    return join(path, "certificate.json");
  }
  return path;
}

function resolveArtifacts(artifacts, config) {
  return Object.fromEntries(Object.entries(artifacts).map(([key, ref]) => [key, resolveArtifactRef(ref, config)]));
}

function resolveArtifactRef(ref, config) {
  if (typeof ref !== "string") {
    return ref;
  }
  if (ref.startsWith("file://")) {
    return fileURLToPath(ref);
  }
  const artifactPrefix = `${config.certificateBaseUrl}/`;
  if (ref.startsWith(artifactPrefix)) {
    const parts = ref.slice(artifactPrefix.length).split("/");
    const [runId, section, artifactName] = parts;
    if (section === "artifacts" && artifactName) {
      const artifactMap = {
        "receipts.jsonl": "receipts.jsonl",
        "keyring.json": "keyring.json",
        "checkpoint.json": "checkpoint.json",
        "transparency-log.jsonl": "transparency-log.jsonl",
        "verification.json": "verification.json",
        "admission-manifest.json": "admission-manifest.json",
        "operator-registry.json": "operator-registry.json",
        "policy-decision.json": "policy-decision.json",
        "policy-bundle.json": "policy-bundle.json",
        "registry-epoch.json": "registry-epoch.json",
        "gateway-attestation.json": "gateway-attestation.json",
        "l1-witness-attestations.json": "l1-witness-attestations.json"
      };
      if (artifactMap[artifactName]) {
        return join(config.dataDir, "runs", runId, artifactMap[artifactName]);
      }
    }
  }
  return ref;
}

function withoutDigest(certificate) {
  const { certificate_digest, ...rest } = certificate;
  return rest;
}

function readJsonl(path) {
  return readFileSync(path, "utf8").split("\n").filter((line) => line.trim()).map((line) => JSON.parse(line));
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

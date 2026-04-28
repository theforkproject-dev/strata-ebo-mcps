import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
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
  verifyCheckpoint,
  verifySession,
  writeCheckpoint
} from "./primitives.js";
import { EMAIL_COMMITMENT_VERSION, EMAIL_PAYLOAD_VERSION, canonicalizeEmailInput, emailCommitment } from "../email/canonical.js";
import { createEmailProvider } from "../email/provider.js";
import { createEmailTool } from "../email/tool.js";

export function createActionRegistry(config) {
  const policyHash = sha256Hex(JSON.stringify({ product: "strata-email-mcp", version: "v1" }));
  return {
    version: "strata.action-registry.v1",
    registry_id: "action-registry.email-mcp",
    epoch_id: "email-mcp-epoch-v1",
    protocol: emailProtocolVersions(),
    tools: [
      {
        name: "gateway_status",
        title: "Check Strata Gateway Status",
        description: "Check email provider configuration and Level 1 witness health before sending.",
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
        description: "Send an email through the Strata Verified Action Gateway. Assurance mode: witnessed. Witness tier: Level 1 mechanical. Quorum: 2-of-3.",
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
          required_witness_tier: "mechanical",
          quorum: { threshold: 2, set: "witness-set.email-mcp.l1" }
        },
        policy: { policy_bundle_hash: policyHash },
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
  const healthyWitnesses = witnessChecks.filter((witness) => witness.ok).length;
  const requiredWitnesses = 2;
  return {
    status: healthyWitnesses >= requiredWitnesses && config.email.provider ? "ready" : "not_ready",
    checked_at: new Date().toISOString(),
    protocol: emailProtocolVersions(),
    assurance: {
      mode: "witnessed",
      witness_tier: "level-1-mechanical",
      witness_quorum_required: "2-of-3",
      witness_quorum_available: `${healthyWitnesses}-of-${config.witnesses.length}`
    },
    receipt_flow: emailReceiptFlow(),
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
    witnesses: witnessChecks
  };
}

function emailProtocolVersions() {
  return {
    commitment_schema_version: EMAIL_COMMITMENT_VERSION,
    payload_schema_version: EMAIL_PAYLOAD_VERSION,
    certificate_schema_version: "strata.email.certificate.v1",
    recipient_verification_schema_version: "strata.recipient.verification_receipt.v1"
  };
}

function emailReceiptFlow() {
  return {
    expected_receipt_count: 6,
    note: "receipt_count counts hash-chained protocol receipts, not the number of witnesses. Witness signatures are embedded in quorum certificates on selected receipts.",
    steps: [
      { index: 0, kind: "session.start", purpose: "Open certified session and bind policy/admission evidence." },
      { index: 1, kind: "tool.request", purpose: "Commit to the requested email send digest before authorization." },
      { index: 2, kind: "intent.grant", purpose: "Gateway grants a single-use capability for this exact send; Level 1 witnesses sign the grant subject." },
      { index: 3, kind: "tool.execution", purpose: "Email adapter verifies the capability, sends via provider, and signs provider message metadata." },
      { index: 4, kind: "observation", purpose: "Gateway observes the tool execution output digest; Level 1 witnesses sign the observation subject." },
      { index: 5, kind: "session.end", purpose: "Close certified session and bind final state." }
    ],
    quorum_semantics: "2-of-3 Level 1 witness quorum is over the intent grant and observed execution, not one receipt per witness."
  };
}

export async function runVerifiedEmailSend(input, config) {
  if (config.witnesses.length < 3) {
    throw new Error("email_send_verified requires three Level 1 witness URLs in WITNESS_URLS");
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
  const keys = loadGatewayKeys(config);
  const keyring = {
    [keys.gateway.signer.keyId]: keys.gateway.publicKeyPem,
    [keys.tool.signer.keyId]: keys.tool.publicKeyPem,
    [keys.transparency.signer.keyId]: keys.transparency.publicKeyPem
  };
  const witnesses = await createWitnessClients(config.witnesses, keyring);
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
  const policyHash = digestValue({ product: "strata-email-mcp", action: "email.send", egressPolicy });
  const verifierProfile = createVerifierProfile({ profile_id: "profile.email-mcp.level1.v1" });
  const admissionManifest = createAdmissionManifest({
    manifestId: "adm_email_mcp_v1",
    governanceId: "gov_email_mcp_v1",
    policyHash,
    agent: tinfoilEvidence("mcp-agent", ["mcp://tools/*"], null),
    gateway: tinfoilEvidence("email-gateway", ["strata://verified-actions/email.send"], egressPolicy),
    verifier: tinfoilEvidence("email-verifier", ["verify://local/email"], null),
    approvedTools: [{ tool_id: "email-api", audience: "email-api", methods: ["POST /v1/send-email"] }],
    approvedDataSources: [],
    approvedModels: [],
    witnessSetId: "witness-set.email-mcp.l1",
    witnessThreshold: 2
  });
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
    sideEffectWitnessThreshold: 2,
    sessionBoundaryWitnessThreshold: 2,
    checkpointWitnessThreshold: 2,
    transparencyLog
  });

  await gateway.startSession({ sessionId: `sess_${runId}`, taskInputDigest: publicCommitment.payload_digest });
  const toolResult = await gateway.toolCall({
    toolName: "email-api",
    method: "POST /v1/send-email",
    request
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
  const ok = session.ok && checkpointResult.ok;
  const verification = { ok, session, checkpoint: checkpointResult };
  writeJson(paths.verification, verification);

  const certificateBody = {
    version: "strata.email.certificate.v1",
    run_id: runId,
    certificate_url: certificateUrl,
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
    proof: {
      assurance_mode: "witnessed",
      witness_tier: "level-1-mechanical",
      witness_quorum: "2-of-3",
      receipt_count: receipts.length,
      checkpoint_id: checkpoint.statement.checkpoint_id,
      receipt_root: session.finalStateRoot,
      verified: ok
    },
    artifacts: {
      receipts: fileRef(paths.receipts),
      keyring: fileRef(paths.keyring),
      checkpoint: fileRef(paths.checkpoint),
      transparency_log: fileRef(paths.transparencyLog),
      verification: fileRef(paths.verification)
    },
    errors: [...session.errors, ...checkpointResult.errors]
  };
  const certificateDigest = digestValue(certificateBody);
  const certificate = { ...certificateBody, certificate_digest: certificateDigest };
  writeJson(paths.certificate, certificate);

  return {
    ok,
    run_id: runId,
    out_dir: outDir,
    certificate_ref: fileRef(outDir),
    certificate_url: certificateUrl,
    certificate_digest: certificateDigest,
    tool_output: toolResult.output,
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
      certificate: paths.certificate,
      receipts: paths.receipts,
      keyring: paths.keyring,
      checkpoint: paths.checkpoint,
      transparency_log: paths.transparencyLog,
      verification: paths.verification
    },
    errors: certificate.errors
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
  const artifacts = resolveArtifacts(certificate.artifacts);
  const receipts = readJsonl(artifacts.receipts);
  const keyring = JSON.parse(readFileSync(artifacts.keyring, "utf8"));
  const checkpoint = JSON.parse(readFileSync(artifacts.checkpoint, "utf8"));
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
  const certificateVerified = session.ok && checkpointResult.ok && digestValue(withoutDigest(certificate)) === certificate.certificate_digest;
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
    content_match: contentMatch,
    certificate_verified: certificateVerified,
    verification_errors: [
      ...session.errors.map((error) => `session: ${error}`),
      ...checkpointResult.errors.map((error) => `checkpoint: ${error}`)
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
    "x-strata-witness-tier": certificate.proof?.witness_tier
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
    certificate: join(outDir, "certificate.json")
  };
}

function loadGatewayKeys(config) {
  const keyDir = join(config.dataDir, "keys");
  mkdirSync(keyDir, { recursive: true });
  return {
    gateway: loadOrCreateEd25519Signer({ keyFile: join(keyDir, "gateway.key.json"), keyId: "gateway:email-mcp" }),
    tool: loadOrCreateEd25519Signer({ keyFile: join(keyDir, "email-tool.key.json"), keyId: "tool:email-api:email-mcp" }),
    transparency: loadOrCreateEd25519Signer({ keyFile: join(keyDir, "transparency.key.json"), keyId: "transparency:email-mcp" })
  };
}

function loadRecipientVerifierKey(config) {
  const keyDir = join(config.dataDir, "keys");
  mkdirSync(keyDir, { recursive: true });
  return loadOrCreateEd25519Signer({ keyFile: join(keyDir, "recipient-verifier.key.json"), keyId: "recipient-verifier:email-mcp" });
}

async function createWitnessClients(specs, keyring) {
  const witnesses = specs.map((spec) => new HttpWitnessClient(spec));
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

function createEgressPolicy(config) {
  const allowedUrls = config.witnesses.map((witness) => witness.url);
  if (config.email.provider === "resend") {
    allowedUrls.push(config.email.resendBaseUrl);
  }
  return {
    mode: "email-provider-and-witness-urls-only",
    allowed_urls: allowedUrls.sort(),
    enforcement: "application-code-typed-adapters",
    evidence_ref: "runtime env WITNESS_URLS + EMAIL_PROVIDER",
    note: "Level 1 demo policy evidence, not a TEE-native network firewall proof."
  };
}

function tinfoilEvidence(containerName, shimPaths, egressPolicy) {
  return createTinfoilEvidence({
    containerName,
    imageDigest: `sha256:${sha256Hex(`email-mcp:${containerName}`)}`,
    configHash: sha256Hex(`email-mcp-config:${containerName}`),
    attestationRef: `demo://email-mcp/${containerName}/attestation-placeholder`,
    sigstoreBundleRef: `sigstore://email-mcp/${containerName}`,
    shimPaths,
    egressPolicy
  });
}

function resolveCertificatePath(ref, config) {
  if (!ref) {
    throw new Error("certificate_ref is required");
  }
  let path;
  if (ref.startsWith("file://")) {
    path = fileURLToPath(ref);
  } else if (ref.startsWith(config.certificateBaseUrl)) {
    const runId = ref.slice(config.certificateBaseUrl.length).replace(/^\//, "");
    path = join(config.dataDir, "runs", runId);
  } else {
    path = ref;
  }
  if (existsSync(join(path, "certificate.json"))) {
    return join(path, "certificate.json");
  }
  return path;
}

function resolveArtifacts(artifacts) {
  return Object.fromEntries(Object.entries(artifacts).map(([key, ref]) => [key, ref.startsWith("file://") ? fileURLToPath(ref) : ref]));
}

function withoutDigest(certificate) {
  const { certificate_digest, ...rest } = certificate;
  return rest;
}

function fileRef(path) {
  return `file://${resolve(path)}`;
}

function readJsonl(path) {
  return readFileSync(path, "utf8").split("\n").filter((line) => line.trim()).map((line) => JSON.parse(line));
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

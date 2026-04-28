#!/usr/bin/env node
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
import {
  ActionGateway,
  DISSENT_CLASSES,
  HttpWitnessClient,
  JsonlReceiptLog,
  LocalTransparencyLog,
  createAdmissionManifest,
  createDissentNotice,
  createSessionReference,
  createSessionSummary,
  createLegacyPaymentsTool,
  createPaymentsTool,
  createTinfoilEvidence,
  createVerifierProfile,
  checkpointDigest,
  sha256Hex,
  verifyCheckpoint,
  verifyCheckpointChain,
  verifyStampedOutput,
  verifySession,
  writeCheckpoint
} from "../src/index.js";

const args = parseArgs(process.argv.slice(2));
const mode = args._[0] ?? "happy";
const outDir = args.out ?? join("artifacts", "demo", mode);

if (!["happy", "tamper", "skipped-step", "paste-laundered", "legacy-tool", "abort", "stream-abort", "side-effect-abort", "dissent", "stamped-output", "cross-session"].includes(mode)) {
  fatal(`Unknown demo mode: ${mode}`);
}

const result = await runDemo({ mode, outDir });
console.log(JSON.stringify(result, null, 2));
process.exitCode = result.verification.ok ? 0 : 1;

async function runDemo({ mode, outDir }) {
  mkdirSync(outDir, { recursive: true });

  const gatewayKeys = generateKeyPairSync("ed25519");
  const toolKeys = generateKeyPairSync("ed25519");
  const transparencyKeys = generateKeyPairSync("ed25519");
  const dissenterKeys = generateKeyPairSync("ed25519");
  const gatewaySigner = { keyId: "gateway:local:demo", privateKey: gatewayKeys.privateKey };
  const toolSigner = { keyId: "tool:payments-api:demo", privateKey: toolKeys.privateKey };
  const transparencySigner = { keyId: "transparency:local:demo", privateKey: transparencyKeys.privateKey };
  const dissenterSigner = { keyId: "dissenter:claim-reviewer:demo", privateKey: dissenterKeys.privateKey };
  const keyring = {
    [gatewaySigner.keyId]: publicKeyPem(gatewayKeys.publicKey),
    [toolSigner.keyId]: publicKeyPem(toolKeys.publicKey),
    [transparencySigner.keyId]: publicKeyPem(transparencyKeys.publicKey),
    [dissenterSigner.keyId]: publicKeyPem(dissenterKeys.publicKey)
  };
  let witnessProcesses = [];

  const keyringPath = join(outDir, "keyring.json");
  const logPath = join(outDir, "receipts.jsonl");
  const transparencyLogPath = join(outDir, "transparency-log.jsonl");
  const checkpointPath = join(outDir, "checkpoint.json");
  const checkpointsPath = join(outDir, "checkpoints.json");
  const stampedOutputPath = join(outDir, "stamped-output.json");

  const clock = fixedClock("2026-04-26T00:00:00.000Z");
  const log = new JsonlReceiptLog(logPath);
  log.reset();
  const transparencyLog = new LocalTransparencyLog({
    filePath: transparencyLogPath,
    signer: transparencySigner,
    logId: "local-demo-transparency-log",
    clock
  });
  transparencyLog.reset();

  let witnesses = [];

  try {
    const launched = await startWitnessProcesses({ outDir });
    witnessProcesses = launched.processes;
    witnesses = launched.clients;
    for (const publicKey of launched.publicKeys) {
      keyring[publicKey.key_id] = publicKey.public_key_pem;
    }
    writeFileSync(keyringPath, `${JSON.stringify(keyring, null, 2)}\n`, "utf8");

    const result = await runDemoWithWitnesses({
      mode,
      outDir,
      log,
      keyring,
      keyringPath,
      logPath,
      transparencyLog,
      transparencyLogPath,
      checkpointPath,
      checkpointsPath,
      stampedOutputPath,
      gatewaySigner,
      toolSigner,
      dissenterSigner,
      witnesses,
      clock
    });
    return result;
  } finally {
    await stopWitnessProcesses(witnessProcesses);
  }
}

async function runDemoWithWitnesses({
  mode,
  outDir,
  log,
  keyring,
  keyringPath,
  logPath,
  transparencyLog,
  transparencyLogPath,
  checkpointPath,
  checkpointsPath,
  stampedOutputPath,
  gatewaySigner,
  toolSigner,
  dissenterSigner,
  witnesses,
  clock
}) {
  const policyHash = sha256Hex("policy:demo:v1");
  const verifierProfile = createVerifierProfile({
    profile_id: "profile.demo.regulated-workflow.v1",
    side_effect_quorum_threshold: 2,
    checkpoint_quorum_threshold: 2
  });
  const admissionManifest = createAdmissionManifest({
    manifestId: "adm_demo_v1",
    governanceId: "gov_demo_v1",
    policyHash,
    agent: createTinfoilEvidence({
      containerName: "agent",
      imageDigest: imageDigest("agent"),
      configHash: sha256Hex("agent-config"),
      attestationRef: "https://agent.demo/.well-known/tinfoil-attestation",
      sigstoreBundleRef: "sigstore://demo/agent",
      shimPaths: []
    }),
    gateway: createTinfoilEvidence({
      containerName: "gateway",
      imageDigest: imageDigest("gateway"),
      configHash: sha256Hex("gateway-config"),
      attestationRef: "https://gateway.demo/.well-known/tinfoil-attestation",
      sigstoreBundleRef: "sigstore://demo/gateway",
      shimPaths: ["/v1/*"],
      egressPolicy: { mode: "typed-adapters-only", evidence_ref: "git://demo/tinfoil-config.yml" }
    }),
    verifier: createTinfoilEvidence({
      containerName: "verifier",
      imageDigest: imageDigest("verifier"),
      configHash: sha256Hex("verifier-config"),
      attestationRef: "https://verifier.demo/.well-known/tinfoil-attestation",
      sigstoreBundleRef: "sigstore://demo/verifier",
      shimPaths: ["/verify"]
    }),
    approvedTools: [
      { tool_id: "payments-api", audience: "payments-api", methods: ["POST /v1/payments"] },
      { tool_id: "legacy-payments-api", audience: "legacy-payments-api", methods: ["POST /v1/payments"], taint_label: "uncertified_tool" }
    ],
    approvedDataSources: ["payments-ledger"],
    approvedModels: ["mock.local"],
    witnessThreshold: 2,
    issuedAt: "2026-04-26T00:00:00.000Z"
  });

  const tool = mode === "legacy-tool" ? createLegacyPaymentsTool({
    signer: toolSigner,
    clock
  }) : createPaymentsTool({
    signer: toolSigner,
    gatewayKeyring: keyring,
    clock
  });
  const gateway = new ActionGateway({
    log,
    signer: gatewaySigner,
    tools: { [tool.name]: tool },
    policyHash,
    verifierProfile,
    admissionManifest,
    witnesses,
    sideEffectWitnessThreshold: 2,
    sessionBoundaryWitnessThreshold: 2,
    transparencyLog,
    clock
  });

  if (mode === "cross-session") {
    return runCrossSessionDemo({
      outDir,
      log,
      keyring,
      keyringPath,
      logPath,
      transparencyLog,
      transparencyLogPath,
      checkpointPath,
      gatewaySigner,
      toolSigner,
      dissenterSigner,
      witnesses,
      clock,
      policyHash,
      verifierProfile,
      admissionManifest
    });
  }

  await gateway.startSession({
    sessionId: "sess_demo",
    taskInputDigest: sha256Hex("pay approved invoice INV-123")
  });
  let checkpoint;
  let checkpoints;
  if (mode === "abort") {
    await gateway.abortModelCall({
      prompt: "Should invoice INV-123 be paid?",
      reason: "model-provider-timeout",
      partialOutput: "partial recommendation before timeout"
    });
    checkpoint = await gateway.createCheckpoint({ checkpointId: `chk_demo_${mode}_0`, checkpointIndex: 0 });
  } else if (mode === "stream-abort") {
    await gateway.abortStreamingModelCall({
      prompt: "Stream a long recommendation for invoice INV-123.",
      reason: "stream-connection-reset",
      streamId: "stream_demo_invoice_123",
      chunks: [
        "The invoice appears to match the approved vendor record.",
        "The amount is within the expected range, but",
        "additional supporting documentation"
      ]
    });
    checkpoint = await gateway.createCheckpoint({ checkpointId: `chk_demo_${mode}_0`, checkpointIndex: 0 });
  } else if (mode === "side-effect-abort") {
    await gateway.modelCall({ prompt: "Should invoice INV-123 be paid?" });
    await gateway.abortToolCall({
      toolName: tool.name,
      method: "POST /v1/payments",
      request: { amount: 1250, currency: "USD", recipient: "vendor_123", invoice_id: "INV-123" },
      reason: "tool-unreachable-after-grant",
      executionStatus: "tool_unreachable"
    });
    checkpoint = await gateway.createCheckpoint({ checkpointId: `chk_demo_${mode}_0`, checkpointIndex: 0 });
  } else {
    const modelResult = await gateway.modelCall({ prompt: "Should invoice INV-123 be paid?" });
    let stampedOutput = null;
    if (mode === "stamped-output") {
      const stampResult = await gateway.stampOutput({
        output: modelResult.output,
        sourceReceiptRoot: modelResult.receipts[1].state_root,
        outputRef: "artifact://demo/model-response.json",
        contentType: "application/json",
        receiptLogRef: logPath,
        certificateRef: checkpointPath,
        transparencyLogRef: transparencyLogPath,
        sinkRef: "customer-facing-system://demo/invoice-review",
        includeTransparency: true
      });
      stampedOutput = stampResult.stamp;
      writeFileSync(stampedOutputPath, `${JSON.stringify(stampedOutput, null, 2)}\n`, "utf8");
    }
    if (mode === "dissent") {
      await gateway.recordDissentNotice(createDissentNotice({
        noticeId: "dn_demo_semantic_1",
        sessionId: "sess_demo",
        targetReceiptHash: modelResult.receipts[1].state_root,
        targetStepIndex: modelResult.receipts[1].step_index,
        noticeClass: DISSENT_CLASSES.SEMANTIC_WARNING_ADVISORY,
        claim: "Model response should be manually reviewed before relying on the recommendation.",
        evidenceRef: "dissent://demo/manual-review-note",
        issuedAt: "2026-04-26T00:00:00.000Z"
      }, dissenterSigner));
    }
    await gateway.humanApproval({
      approver: "human:finance-ops",
      question: "Approve payment for invoice INV-123?",
      context: { invoice_id: "INV-123", amount: 1250 },
      approved: true
    });
    await gateway.toolCall({
      toolName: tool.name,
      method: "POST /v1/payments",
      request: { amount: 1250, currency: "USD", recipient: "vendor_123", invoice_id: "INV-123" },
      inputEdges: mode === "paste-laundered" ? [
        {
          edge_id: "input_operator_paste_1",
          source_type: "operator.paste",
          digest: sha256Hex("operator pasted uncertified invoice note"),
          taint_label: "uncertified_input"
        }
      ] : []
    });
    checkpoint = await gateway.createCheckpoint({ checkpointId: `chk_demo_${mode}_0`, checkpointIndex: 0 });
  }
  await gateway.dataQuery({
    source: "payments-ledger",
    query: "select payment status",
    parameters: { invoice_id: "INV-123" }
  });
  const secondCheckpoint = await gateway.createCheckpoint({
    checkpointId: `chk_demo_${mode}_1`,
    checkpointIndex: 1,
    prevCheckpointHash: checkpointDigest(checkpoint)
  });
  checkpoints = [checkpoint, secondCheckpoint];
  writeFileSync(checkpointsPath, `${JSON.stringify(checkpoints, null, 2)}\n`, "utf8");
  writeCheckpoint(checkpointPath, secondCheckpoint);
  await gateway.endSession();

  if (mode === "tamper") {
    const receipts = log.readAll();
    const executionIndex = receipts.findIndex((receipt) => receipt.kind === "tool.execution");
    receipts[executionIndex].body.output_digest = sha256Hex("tampered payment result");
    log.writeAll(receipts);
  }

  if (mode === "skipped-step") {
    const receipts = log.readAll();
    const observationIndex = receipts.findIndex((receipt) => receipt.kind === "observation");
    receipts.splice(observationIndex, 1);
    log.writeAll(receipts);
  }

  const receipts = log.readAll();
  const transparencyLogEntries = transparencyLog.readAll();
  const sessionResult = verifySession(receipts, keyring, {
    now: "2026-04-26T00:01:00.000Z",
    transparencyLogEntries,
    requireAdmissionManifest: true,
    requireSideEffectQuorum: true,
    requireBoundaryQuorum: true,
    requireTransparencyLog: true
  });
  if (mode === "stamped-output") {
    sessionResult.errors.push(...verifyAllStampedOutputs({
      receipts,
      keyring,
      transparencyLogEntries,
      requireTransparencyLog: true
    }).errors);
    sessionResult.ok = sessionResult.errors.length === 0;
  }
  const checkpointResult = verifyCheckpointChain(checkpoints, receipts, keyring, {
    transparencyLogEntries,
    requireCheckpointQuorum: true,
    requireCheckpointTransparency: true
  });

  return {
    mode,
    out_dir: outDir,
    log_path: logPath,
    transparency_log_path: transparencyLogPath,
    keyring_path: keyringPath,
    checkpoint_path: checkpointPath,
    checkpoints_path: checkpointsPath,
    stamped_output_path: mode === "stamped-output" ? stampedOutputPath : undefined,
    verification: {
      ok: sessionResult.ok && checkpointResult.ok,
      session: sessionResult,
      checkpoint: checkpointResult
    }
  };
}

function verifyAllStampedOutputs({ receipts, keyring, transparencyLogEntries, requireTransparencyLog }) {
  const errors = [];
  for (const [index, receipt] of receipts.entries()) {
    if (receipt.kind !== "output.stamped") {
      continue;
    }
    const result = verifyStampedOutput(receipt.body.stamped_output, {
      receipts,
      keyring,
      transparencyLogEntries,
      requireTransparencyLog
    });
    errors.push(...result.errors.map((error) => `receipt ${index} stamped output: ${error}`));
  }
  return { ok: errors.length === 0, errors };
}

async function runCrossSessionDemo({
  outDir,
  log,
  keyring,
  keyringPath,
  logPath,
  transparencyLog,
  transparencyLogPath,
  checkpointPath,
  gatewaySigner,
  toolSigner,
  dissenterSigner,
  witnesses,
  clock,
  policyHash,
  verifierProfile,
  admissionManifest
}) {
  const priorLogPath = join(outDir, "prior-receipts.jsonl");
  const priorCheckpointPath = join(outDir, "prior-checkpoint.json");
  const priorSummaryPath = join(outDir, "prior-summary.json");
  const priorLog = new JsonlReceiptLog(priorLogPath);
  priorLog.reset();
  const priorGateway = new ActionGateway({
    log: priorLog,
    signer: gatewaySigner,
    tools: { "payments-api": createPaymentsTool({ signer: toolSigner, gatewayKeyring: keyring, clock }) },
    policyHash,
    verifierProfile,
    admissionManifest,
    witnesses,
    sideEffectWitnessThreshold: 2,
    sessionBoundaryWitnessThreshold: 2,
    transparencyLog,
    clock
  });

  await priorGateway.startSession({
    sessionId: "sess_prior",
    taskInputDigest: sha256Hex("prior claim review")
  });
  const priorModel = await priorGateway.modelCall({ prompt: "Assess prior claim context." });
  await priorGateway.recordDissentNotice(createDissentNotice({
    noticeId: "dn_prior_semantic_1",
    sessionId: "sess_prior",
    targetReceiptHash: priorModel.receipts[1].state_root,
    targetStepIndex: priorModel.receipts[1].step_index,
    noticeClass: DISSENT_CLASSES.SEMANTIC_WARNING_ADVISORY,
    claim: "Prior session output has unresolved semantic review warning.",
    evidenceRef: "dissent://demo/prior-review-warning",
    issuedAt: "2026-04-26T00:00:00.000Z"
  }, dissenterSigner));
  const priorCheckpoint = await priorGateway.createCheckpoint({ checkpointId: "chk_demo_cross_session_prior", checkpointIndex: 0 });
  writeCheckpoint(priorCheckpointPath, priorCheckpoint);
  await priorGateway.endSession();

  const priorReceipts = priorLog.readAll();
  const priorSessionResult = verifySession(priorReceipts, keyring, {
    now: "2026-04-26T00:01:00.000Z",
    transparencyLogEntries: transparencyLog.readAll(),
    requireAdmissionManifest: true,
    requireBoundaryQuorum: true,
    requireTransparencyLog: true
  });
  const priorCheckpointResult = verifyCheckpoint(priorCheckpoint, priorReceipts, keyring, {
    transparencyLogEntries: transparencyLog.readAll(),
    requireCheckpointQuorum: true,
    requireCheckpointTransparency: true
  });
  const priorSummary = createSessionSummary({ receipts: priorReceipts, verification: priorSessionResult, checkpoint: priorCheckpoint });
  writeFileSync(priorSummaryPath, `${JSON.stringify(priorSummary, null, 2)}\n`, "utf8");
  const priorReference = createSessionReference({
    referenceId: "ref_prior_claim_context",
    summary: priorSummary,
    dependencyType: "prior-output",
    importedReceiptHash: priorModel.receipts[1].state_root,
    importedOutputDigest: priorModel.receipts[1].body.output_digest,
    purpose: "Use prior claim context while preserving dissent status."
  });

  const gateway = new ActionGateway({
    log,
    signer: gatewaySigner,
    tools: { "payments-api": createPaymentsTool({ signer: toolSigner, gatewayKeyring: keyring, clock }) },
    policyHash,
    verifierProfile,
    admissionManifest,
    witnesses,
    sideEffectWitnessThreshold: 2,
    sessionBoundaryWitnessThreshold: 2,
    transparencyLog,
    clock
  });

  await gateway.startSession({
    sessionId: "sess_demo",
    taskInputDigest: sha256Hex("dependent claim review"),
    crossSessionReferences: [priorReference]
  });
  await gateway.modelCall({ prompt: "Continue claim assessment using prior certified context." });
  const checkpoint = await gateway.createCheckpoint({ checkpointId: "chk_demo_cross_session", checkpointIndex: 0 });
  writeCheckpoint(checkpointPath, checkpoint);
  await gateway.endSession();

  const receipts = log.readAll();
  const transparencyLogEntries = transparencyLog.readAll();
  const sessionResult = verifySession(receipts, keyring, {
    now: "2026-04-26T00:01:00.000Z",
    transparencyLogEntries,
    priorSessionSummaries: [priorSummary],
    requireCrossSessionSummaries: true,
    requireAdmissionManifest: true,
    requireBoundaryQuorum: true,
    requireTransparencyLog: true
  });
  const checkpointResult = verifyCheckpoint(checkpoint, receipts, keyring, {
    transparencyLogEntries,
    requireCheckpointQuorum: true,
    requireCheckpointTransparency: true
  });

  return {
    mode: "cross-session",
    out_dir: outDir,
    prior_log_path: priorLogPath,
    prior_checkpoint_path: priorCheckpointPath,
    prior_summary_path: priorSummaryPath,
    log_path: logPath,
    transparency_log_path: transparencyLogPath,
    keyring_path: keyringPath,
    checkpoint_path: checkpointPath,
    prior_summary: priorSummary,
    verification: {
      ok: priorSessionResult.ok && priorCheckpointResult.ok && sessionResult.ok && checkpointResult.ok,
      prior_session: priorSessionResult,
      prior_checkpoint: priorCheckpointResult,
      session: sessionResult,
      checkpoint: checkpointResult
    }
  };
}

async function startWitnessProcesses({ outDir }) {
  const processes = [];
  const clients = [];
  const publicKeys = [];
  const basePort = 20000 + Math.floor(Math.random() * 20000);

  for (let index = 1; index <= 3; index += 1) {
    const witnessId = `w${index}`;
    const keyFile = join(outDir, `witness-${index}.key.json`);
    const walPath = join(outDir, `witness-${index}.jsonl`);
    rmSync(keyFile, { force: true });
    rmSync(walPath, { force: true });

    const child = spawn(process.execPath, [
      "bin/turnstile-witness.js",
      "--host", "127.0.0.1",
      "--port", String(basePort + index),
      "--witness-id", witnessId,
      "--key-id", `witness:${witnessId}:demo`,
      "--key-file", keyFile,
      "--wal", walPath
    ], {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"]
    });
    processes.push(child);

    const started = await waitForWitnessStart(child);
    clients.push(new HttpWitnessClient({ id: started.witness_id, url: started.url }));
    publicKeys.push({ key_id: started.key_id, public_key_pem: started.public_key_pem });
  }

  return { processes, clients, publicKeys };
}

function waitForWitnessStart(child) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      reject(new Error(`Timed out waiting for witness start: ${stderr}`));
    }, 5000);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
      const line = stdout.split("\n").find((item) => item.trim().startsWith("{"));
      if (!line) {
        return;
      }

      clearTimeout(timer);
      resolve(JSON.parse(line));
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });

    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`Witness exited before start with code ${code}: ${stderr}`));
    });
  });
}

async function stopWitnessProcesses(processes) {
  await Promise.all(processes.map((child) => new Promise((resolve) => {
    if (child.exitCode !== null || child.killed) {
      resolve();
      return;
    }
    child.once("exit", () => resolve());
    child.kill("SIGTERM");
    setTimeout(() => {
      if (child.exitCode === null && !child.killed) {
        child.kill("SIGKILL");
      }
      resolve();
    }, 1000);
  })));
}

function publicKeyPem(publicKey) {
  return publicKey.export({ type: "spki", format: "pem" });
}

function fixedClock(iso) {
  return () => new Date(iso);
}

function imageDigest(label) {
  return `sha256:${sha256Hex(`image:${label}`)}`;
}

function parseArgs(argv) {
  const parsed = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (item.startsWith("--")) {
      parsed[item.slice(2)] = argv[index + 1];
      index += 1;
    } else {
      parsed._.push(item);
    }
  }
  return parsed;
}

function fatal(message) {
  console.error(message);
  process.exit(2);
}

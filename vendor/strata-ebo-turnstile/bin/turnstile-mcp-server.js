#!/usr/bin/env node
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import {
  ActionGateway,
  JsonlReceiptLog,
  LocalTransparencyLog,
  Witness,
  createAdmissionManifest,
  createPaymentsTool,
  createTinfoilEvidence,
  createVerifierProfile,
  sha256Hex,
  verifyCheckpoint,
  verifySession,
  writeCheckpoint
} from "../src/index.js";

const PROTOCOL_VERSION = "2025-11-25";
const args = parseArgs(process.argv.slice(2));
const rootOutDir = args.out ?? join("artifacts", "mcp-demo", new Date().toISOString().replace(/[:.]/g, "-"));
const actionRegistry = createActionRegistry();
let latestRun = null;

process.stdin.setEncoding("utf8");
let input = "";
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const newline = input.indexOf("\n");
    if (newline === -1) {
      break;
    }
    const line = input.slice(0, newline).trim();
    input = input.slice(newline + 1);
    if (line) {
      handleLine(line);
    }
  }
});

async function handleLine(line) {
  let message;
  try {
    message = JSON.parse(line);
  } catch (error) {
    return sendError(null, -32700, `Parse error: ${error.message}`);
  }

  if (!message.id && message.method?.startsWith("notifications/")) {
    return;
  }

  try {
    switch (message.method) {
      case "initialize":
        return sendResult(message.id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: {
            tools: { listChanged: false },
            resources: { listChanged: false }
          },
          serverInfo: {
            name: "strata-verified-actions-demo",
            title: "Strata Verified Actions Demo MCP Server",
            version: "0.1.0",
            description: "Local MCP surface for TURNSTILE Level 1 witnessed actions."
          },
          instructions: "Call tools/list to discover Verified Actions. Use strata.verified.payment.create to execute a local Level 1 witnessed payment action."
        });

      case "tools/list":
        return sendResult(message.id, { tools: actionRegistry.tools });

      case "tools/call":
        return sendResult(message.id, await callTool(message.params ?? {}));

      case "resources/list":
        return sendResult(message.id, { resources: listResources() });

      case "resources/read":
        return sendResult(message.id, readResource(message.params?.uri));

      default:
        return sendError(message.id, -32601, `Method not found: ${message.method}`);
    }
  } catch (error) {
    return sendError(message.id, -32603, error.message);
  }
}

async function callTool(params) {
  if (params.name !== "strata.verified.payment.create") {
    throw new Error(`Unknown tool: ${params.name}`);
  }

  const input = params.arguments ?? {};
  validatePaymentInput(input);
  const run = await runVerifiedPayment(input);
  latestRun = run;

  const structuredContent = {
    status: run.ok ? "executed" : "verification_failed",
    tool_output: run.tool_output,
    verification_tier: "mechanical",
    witness_quorum: "2-of-3",
    certificate_ref: `file://${resolve(run.outDir)}`,
    receipt_count: run.receipt_count,
    checkpoint_id: run.checkpoint_id,
    receipt_root: run.final_state_root,
    verified: run.ok,
    artifacts: run.artifacts
  };

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(structuredContent, null, 2)
      }
    ],
    structuredContent,
    isError: !run.ok
  };
}

async function runVerifiedPayment(input) {
  const runId = `mcp_${Date.now()}`;
  const outDir = join(rootOutDir, runId);
  mkdirSync(outDir, { recursive: true });

  const gatewayKeys = generateKeyPairSync("ed25519");
  const toolKeys = generateKeyPairSync("ed25519");
  const transparencyKeys = generateKeyPairSync("ed25519");
  const gatewaySigner = { keyId: "gateway:mcp-demo", privateKey: gatewayKeys.privateKey };
  const toolSigner = { keyId: "tool:payments-api:mcp-demo", privateKey: toolKeys.privateKey };
  const transparencySigner = { keyId: "transparency:mcp-demo", privateKey: transparencyKeys.privateKey };
  const keyring = {
    [gatewaySigner.keyId]: publicKeyPem(gatewayKeys.publicKey),
    [toolSigner.keyId]: publicKeyPem(toolKeys.publicKey),
    [transparencySigner.keyId]: publicKeyPem(transparencyKeys.publicKey)
  };

  const witnesses = [];
  for (let index = 1; index <= 3; index += 1) {
    const witnessKeys = generateKeyPairSync("ed25519");
    const signer = { keyId: `witness:w${index}:mcp-demo`, privateKey: witnessKeys.privateKey };
    keyring[signer.keyId] = publicKeyPem(witnessKeys.publicKey);
    witnesses.push(new Witness({
      id: `w${index}`,
      signer,
      walPath: join(outDir, `witness-${index}.wal.jsonl`)
    }));
  }

  const logPath = join(outDir, "receipts.jsonl");
  const transparencyLogPath = join(outDir, "transparency-log.jsonl");
  const checkpointPath = join(outDir, "checkpoint.json");
  const keyringPath = join(outDir, "keyring.json");
  const log = new JsonlReceiptLog(logPath);
  log.reset();
  const transparencyLog = new LocalTransparencyLog({ filePath: transparencyLogPath, signer: transparencySigner, logId: "mcp-demo-transparency-log" });
  transparencyLog.reset();

  const policyHash = sha256Hex("policy:mcp-demo:v1");
  const verifierProfile = createVerifierProfile({ profile_id: "profile.mcp-demo.mechanical.v1" });
  const admissionManifest = createAdmissionManifest({
    manifestId: "adm_mcp_demo_v1",
    governanceId: "gov_mcp_demo_v1",
    policyHash,
    agent: tinfoilEvidence("mcp-agent", []),
    gateway: tinfoilEvidence("mcp-gateway", ["mcp://tools/*"], { mode: "mcp-verified-actions-only", evidence_ref: "examples/mcp/action-registry" }),
    verifier: tinfoilEvidence("mcp-verifier", ["verify://local"], null),
    approvedTools: [{ tool_id: "payments-api", audience: "payments-api", methods: ["POST /v1/payments"] }],
    approvedDataSources: [],
    approvedModels: [],
    witnessSetId: "witness-set.mcp-demo.l1",
    witnessThreshold: 2
  });
  const tool = createPaymentsTool({ signer: toolSigner, gatewayKeyring: keyring });
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
    checkpointWitnessThreshold: 2,
    transparencyLog
  });

  await gateway.startSession({
    sessionId: `sess_${runId}`,
    taskInputDigest: sha256Hex(JSON.stringify(input))
  });
  const toolResult = await gateway.toolCall({
    toolName: "payments-api",
    method: "POST /v1/payments",
    request: input
  });
  await gateway.endSession("complete");
  const checkpoint = await gateway.createCheckpoint({ checkpointId: `chk_${runId}` });
  writeCheckpoint(checkpointPath, checkpoint);
  writeFileSync(keyringPath, `${JSON.stringify(keyring, null, 2)}\n`, "utf8");

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
  writeFileSync(join(outDir, "verification.json"), `${JSON.stringify(verification, null, 2)}\n`, "utf8");
  writeFileSync(join(outDir, "action-registry.json"), `${JSON.stringify(actionRegistry, null, 2)}\n`, "utf8");

  return {
    ok,
    outDir,
    tool_output: toolResult.output,
    receipt_count: receipts.length,
    checkpoint_id: checkpoint.statement.checkpoint_id,
    final_state_root: session.finalStateRoot,
    artifacts: {
      receipts: logPath,
      keyring: keyringPath,
      checkpoint: checkpointPath,
      transparency_log: transparencyLogPath,
      verification: join(outDir, "verification.json"),
      action_registry: join(outDir, "action-registry.json")
    },
    errors: [...session.errors, ...checkpointResult.errors]
  };
}

function listResources() {
  const resources = [
    {
      uri: "strata://action-registry/current",
      name: "current-action-registry",
      title: "Current Verified Action Registry",
      description: "MCP projection of the local demo action registry.",
      mimeType: "application/json"
    }
  ];
  if (latestRun) {
    resources.push({
      uri: "strata://certificate/latest",
      name: "latest-certificate",
      title: "Latest MCP Verified Action Certificate",
      description: "Artifact references for the latest local MCP Verified Action run.",
      mimeType: "application/json"
    });
  }
  return resources;
}

function readResource(uri) {
  if (uri === "strata://action-registry/current") {
    return { contents: [{ uri, mimeType: "application/json", text: JSON.stringify(actionRegistry, null, 2) }] };
  }
  if (uri === "strata://certificate/latest" && latestRun) {
    return { contents: [{ uri, mimeType: "application/json", text: JSON.stringify(latestRun, null, 2) }] };
  }
  throw new Error(`Resource not found: ${uri}`);
}

function createActionRegistry() {
  return {
    version: "strata.action-registry.v1",
    registry_id: "action-registry.mcp-demo",
    epoch_id: "mcp-demo-epoch-v1",
    tools: [
      {
        name: "strata.verified.payment.create",
        title: "Create Verified Demo Payment",
        description: "Create a mock payment through the Strata Verified Actions gateway. The tool returns a normal payment result plus certificate metadata. Assurance mode: witnessed. Witness tier: Level 1 mechanical. Quorum: 2-of-3.",
        inputSchema: {
          type: "object",
          properties: {
            amount: { type: "number", description: "Payment amount" },
            currency: { type: "string", description: "Three-letter currency code" },
            recipient: { type: "string", description: "Recipient identifier" }
          },
          required: ["amount", "currency", "recipient"],
          additionalProperties: false
        },
        outputSchema: {
          type: "object",
          properties: {
            status: { type: "string" },
            tool_output: { type: "object" },
            certificate_ref: { type: "string" },
            receipt_count: { type: "number" },
            checkpoint_id: { type: "string" },
            witness_quorum: { type: "string" },
            verified: { type: "boolean" }
          },
          required: ["status", "tool_output", "certificate_ref", "verified"]
        },
        annotations: {
          title: "Verified payment action",
          destructiveHint: true,
          idempotentHint: false,
          openWorldHint: false
        }
      }
    ],
    actions: [
      {
        action_id: "payment.create",
        mcp_tool_name: "strata.verified.payment.create",
        assurance: {
          mode: "witnessed",
          required_witness_tier: "mechanical",
          quorum: { threshold: 2, set: "witness-set.mcp-demo.l1" }
        },
        policy: { policy_bundle_hash: sha256Hex("policy:mcp-demo:v1") },
        adapter: { adapter_id: "mock-payments-api", implementation: "in-process demo adapter" }
      }
    ]
  };
}

function validatePaymentInput(input) {
  for (const field of ["amount", "currency", "recipient"]) {
    if (input[field] === undefined || input[field] === null || input[field] === "") {
      throw new Error(`Missing required field: ${field}`);
    }
  }
  if (typeof input.amount !== "number" || !Number.isFinite(input.amount) || input.amount <= 0) {
    throw new Error("amount must be a positive number");
  }
}

function sendResult(id, result) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
}

function sendError(id, code, message, data = undefined) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, error: { code, message, ...(data ? { data } : {}) } })}\n`);
}

function publicKeyPem(publicKey) {
  return publicKey.export({ type: "spki", format: "pem" });
}

function tinfoilEvidence(containerName, shimPaths, egressPolicy = null) {
  return createTinfoilEvidence({
    containerName,
    imageDigest: `sha256:${sha256Hex(`mcp:${containerName}`)}`,
    configHash: sha256Hex(`mcp-config:${containerName}`),
    attestationRef: `mcp://local/${containerName}/attestation-placeholder`,
    sigstoreBundleRef: `sigstore://mcp-demo/${containerName}`,
    shimPaths,
    egressPolicy
  });
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) {
      continue;
    }
    parsed[item.slice(2)] = argv[index + 1] ?? "true";
    if (argv[index + 1] && !argv[index + 1].startsWith("--")) {
      index += 1;
    }
  }
  return parsed;
}

#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { loadOrCreateEd25519Signer } from "../src/strata/primitives.js";

const root = resolve(new URL("..", import.meta.url).pathname);
const turnstileRoot = resolve(root, "..", "strata-ebo-turnstile");
const dataDir = process.env.DATA_DIR || join(root, "artifacts", "email-mcp-tinfoil");
const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 8899);
const policyWitnessPorts = [9201, 9202, 9203];
const registryPort = 9301;
const witnessUrl = process.env.TINFOIL_EMAIL_L1_WITNESS_URL
  || process.env.TINFOIL_WITNESS_POC_URL
  || "https://strata-witness-poc-1.amotivv.containers.tinfoil.dev";
const witnessUrls = process.env.WITNESS_URLS || `strata-witness-poc-1=${witnessUrl}`;
const gatewayKeyBundleFile = process.env.GATEWAY_KEY_BUNDLE_FILE
  || process.env.TINFOIL_WITNESS_POC_GATEWAY_KEY_FILE
  || join(turnstileRoot, "artifacts", "tinfoil-witness-poc", "gateway-registry-keys.json");
const children = [];
const operatorAdmissionKeyId = "operator-admission:amotivv-demo";
const operatorAdmissionKeyFile = join(dataDir, "keys", "operator-admission.key.json");
const operatorAdmissionKey = loadOrCreateEd25519Signer({ keyFile: operatorAdmissionKeyFile, keyId: operatorAdmissionKeyId });

mkdirSync(dataDir, { recursive: true });

try {
  const policyWitnessUrls = await startPolicyWitnesses();
  const registryUrl = await startRegistry(witnessUrls, policyWitnessUrls);
  const server = startServer(witnessUrls, policyWitnessUrls, registryUrl);
  children.push(server);
  await waitForHealth(`http://${host}:${port}/health`);

  const client = createMcpClient(`http://${host}:${port}/mcp`);
  await client.call("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "strata-email-tinfoil-witness-demo-client", version: "0.1.0" }
  });
  const tools = await client.call("tools/list");
  const status = await client.call("tools/call", { name: "gateway_status", arguments: {} });
  const actionRegistry = await client.call("resources/read", { uri: "strata://action-registry/current" });

  const email = {
    to: [process.env.DEMO_EMAIL_TO || "jason@amotivv.com"],
    subject: "[Verified] Tinfoil witness email gateway demo",
    text: "This dry-run email was routed through the Strata Email MCP gateway and signed by the live Tinfoil L1 witness.",
    tags: { conversation_id: "demo-tinfoil-witness", turn_id: "1", demo: "strata-email-mcp-tinfoil" }
  };
  const preview = await client.call("tools/call", { name: "email_preview", arguments: email });
  const sent = await client.call("tools/call", { name: "email_send_verified", arguments: email });
  if (sent.result.isError) {
    throw new Error(`email_send_verified failed: ${sent.result.content?.[0]?.text || "unknown error"}`);
  }
  const certificate = await client.call("resources/read", { uri: "strata://certificate/latest" });
  const sendResult = sent.result.structuredContent;
  const bundle = await fetch(sendResult.bundle_url).then((response) => response.json());
  const l1GuardEvidence = collectGuardEvidence(bundle);

  console.log(JSON.stringify({
    ok: sendResult.verified === true && l1GuardEvidence.length > 0,
    discovered_tools: tools.result.tools.map((tool) => tool.name),
    gateway_status: status.result.structuredContent.status,
    l1_witness: {
      urls: witnessUrls,
      threshold: status.result.structuredContent.assurance.mechanical_witness_quorum_required,
      signed_requests: status.result.structuredContent.assurance.signed_l1_witness_requests,
      workflow_id: status.result.structuredContent.assurance.signed_l1_witness_workflow_id
    },
    action_registry_resource_bytes: actionRegistry.result.contents[0].text.length,
    preview: preview.result.structuredContent,
    send: sendResult,
    certificate_resource_bytes: certificate.result.contents[0].text.length,
    bundle: {
      version: bundle.version,
      receipt_count: bundle.receipts.length,
      has_keyring: Boolean(bundle.keyring),
      has_policy_decision: Boolean(bundle.policy_decision),
      has_policy_bundle: Boolean(bundle.policy_bundle),
      has_admission_manifest: Boolean(bundle.admission_manifest),
      has_operator_registry: Boolean(bundle.operator_registry),
      has_registry_epoch: Boolean(bundle.registry_epoch),
      l1_guard_evidence_count: l1GuardEvidence.length,
      l1_guard_backends: [...new Set(l1GuardEvidence.map((item) => item.backend))],
      policy_url: bundle.certificate.policy.policy_url
    }
  }, null, 2));
} finally {
  for (const child of children.reverse()) {
    child.kill("SIGTERM");
  }
}

async function startPolicyWitnesses() {
  const urls = [];
  for (let index = 0; index < policyWitnessPorts.length; index += 1) {
    const id = `p${index + 1}`;
    const port = policyWitnessPorts[index];
    const child = spawn(process.execPath, [
      join(root, "bin", "policy-witness.js"),
      "--host", host,
      "--port", String(port),
      "--witness-id", id,
      "--key-file", join(dataDir, "policy-witnesses", `${id}.key.json`)
    ], { stdio: ["ignore", "pipe", "pipe"] });
    children.push(child);
    child.stderr.on("data", (chunk) => process.stderr.write(chunk));
    const info = await waitForJsonLine(child.stdout);
    urls.push(`${id}=${info.url}`);
  }
  return urls.join(",");
}

async function startRegistry(l1WitnessUrls, policyWitnessUrls) {
  const child = spawn(process.execPath, [join(root, "bin", "registry-server.js")], {
    cwd: root,
    env: {
      ...process.env,
      HOST: host,
      PORT: String(registryPort),
      DATA_DIR: dataDir,
      REGISTRY_KEY_FILE: join(dataDir, "registry", "registry-authority.key.json"),
      WITNESS_URLS: l1WitnessUrls,
      POLICY_WITNESS_URLS: policyWitnessUrls,
      TENANT_ID: "default",
      OPERATOR_ID: "operator:amotivv-demo",
      OPERATOR_ADMISSION_KEY_ID: operatorAdmissionKeyId,
      OPERATOR_ADMISSION_PUBLIC_KEY_PEM: operatorAdmissionKey.publicKeyPem
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  children.push(child);
  child.stderr.on("data", (chunk) => process.stderr.write(chunk));
  const info = await waitForJsonLine(child.stdout);
  return info.url;
}

function startServer(l1WitnessUrls, policyWitnessUrls, registryUrl) {
  const env = {
    ...process.env,
    HOST: host,
    PORT: String(port),
    EMAIL_PROVIDER: process.env.EMAIL_PROVIDER || "dry-run",
    EMAIL_FROM: process.env.EMAIL_FROM || "strata-mcp@theforkproject.com",
    DATA_DIR: dataDir,
    PUBLIC_BASE_URL: `http://${host}:${port}`,
    CERTIFICATE_BASE_URL: `http://${host}:${port}/certificates`,
    WITNESS_URLS: l1WitnessUrls,
    WITNESS_THRESHOLD: "1",
    GATEWAY_SIGNED_WITNESS_REQUESTS_ENABLED: "true",
    GATEWAY_KEY_BUNDLE_FILE: gatewayKeyBundleFile,
    WITNESS_EPOCH_ID: process.env.WITNESS_EPOCH_ID || "wit_epoch_tinfoil_poc_002",
    REGISTRY_EPOCH_ID: process.env.REGISTRY_EPOCH_ID || "registry_epoch_tinfoil_poc_002",
    WITNESS_WORKFLOW_ID: process.env.WITNESS_WORKFLOW_ID || "email.send",
    POLICY_WITNESS_URLS: policyWitnessUrls,
    POLICY_WITNESS_THRESHOLD: "2",
    REGISTRY_URL: registryUrl,
    TENANT_ID: "default",
    OPERATOR_ID: "operator:amotivv-demo",
    OPERATOR_ADMISSION_KEY_ID: operatorAdmissionKeyId,
    OPERATOR_ADMISSION_KEY_FILE: operatorAdmissionKeyFile,
    MCP_SESSION_SECRET: process.env.MCP_SESSION_SECRET || "local-demo-session-secret-32-bytes-minimum"
  };
  const child = spawn(process.execPath, [join(root, "src", "server.js")], {
    cwd: root,
    env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  child.stdout.on("data", (chunk) => process.stderr.write(chunk));
  child.stderr.on("data", (chunk) => process.stderr.write(chunk));
  return child;
}

function createMcpClient(url) {
  let id = 1;
  let sessionId = null;
  return {
    async call(method, params = {}) {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(sessionId ? { "mcp-session-id": sessionId } : {})
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: id++, method, params })
      });
      sessionId = response.headers.get("mcp-session-id") || sessionId;
      const body = await response.json();
      if (body.error) {
        throw new Error(`${method} failed: ${body.error.message}`);
      }
      return body;
    }
  };
}

function collectGuardEvidence(bundle) {
  const found = [];
  for (const receipt of bundle.receipts ?? []) {
    for (const signature of receipt.body?.quorum_certificate?.signatures ?? []) {
      if (signature.guard_log) {
        found.push(signature.guard_log);
      }
    }
  }
  if (bundle.checkpoint?.quorum_certificate) {
    for (const signature of bundle.checkpoint.quorum_certificate.signatures ?? []) {
      if (signature.guard_log) {
        found.push(signature.guard_log);
      }
    }
  }
  return found;
}

async function waitForHealth(url) {
  const deadline = Date.now() + 5000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch (error) {
      lastError = error;
    }
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${url}: ${lastError?.message || "not ready"}`);
}

function waitForJsonLine(stream) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const onData = (chunk) => {
      buffer += chunk.toString("utf8");
      const newline = buffer.indexOf("\n");
      if (newline === -1) {
        return;
      }
      stream.off("data", onData);
      try {
        resolve(JSON.parse(buffer.slice(0, newline)));
      } catch (error) {
        reject(error);
      }
    };
    stream.on("data", onData);
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

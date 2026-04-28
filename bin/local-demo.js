#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const strataRoot = resolve(root, "vendor/strata-ebo-turnstile");
const dataDir = process.env.DATA_DIR || join(root, "artifacts", "email-mcp");
const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 8899);
const witnessPorts = [9101, 9102, 9103];
const policyWitnessPorts = [9201, 9202, 9203];
const registryPort = 9301;
const children = [];

mkdirSync(dataDir, { recursive: true });

try {
  const witnessUrls = await startWitnesses();
  const policyWitnessUrls = await startPolicyWitnesses();
  const registryUrl = await startRegistry(witnessUrls, policyWitnessUrls);
  const server = startServer(witnessUrls, policyWitnessUrls, registryUrl);
  children.push(server);
  await waitForHealth(`http://${host}:${port}/health`);

  const client = createMcpClient(`http://${host}:${port}/mcp`);
  await client.call("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "strata-email-demo-client", version: "0.1.0" }
  });
  const tools = await client.call("tools/list");
  const status = await client.call("tools/call", { name: "gateway_status", arguments: {} });
  const registry = await client.call("resources/read", { uri: "strata://action-registry/current" });

  const deniedEmail = {
    to: ["someone@gmail.com"],
    subject: "Policy denial demo",
    text: "This email should be denied by Level 2 policy witnesses.",
    tags: { conversation_id: "demo-local", turn_id: "denied" }
  };
  const denied = await client.call("tools/call", { name: "email_send_verified", arguments: deniedEmail });

  const email = {
    to: ["jason@amotivv.com"],
    subject: "[Verified] Verified agent email demo",
    text: "This dry-run email was routed through the Strata Verified Action Gateway.",
    tags: { conversation_id: "demo-local", turn_id: "1", demo: "strata-email-mcp" }
  };
  const preview = await client.call("tools/call", { name: "email_preview", arguments: email });
  const sent = await client.call("tools/call", { name: "email_send_verified", arguments: email });
  if (sent.result.isError) {
    throw new Error(`email_send_verified failed: ${sent.result.content?.[0]?.text || "unknown error"}`);
  }
  const certificate = await client.call("resources/read", { uri: "strata://certificate/latest" });
  const sendResult = sent.result.structuredContent;
  const receivedEmail = {
    to: email.to,
    subject: email.subject,
    text: `${email.text}\r\n`,
    headers: sendResult.certificate_transmission.in_band_headers
  };
  const recipientVerification = await client.call("tools/call", {
    name: "email_verify_received",
    arguments: {
      certificate_ref: sendResult.bundle_url,
      received: receivedEmail
    }
  });
  const bundle = await fetch(sendResult.bundle_url).then((response) => response.json());

  console.log(JSON.stringify({
    ok: true,
    discovered_tools: tools.result.tools.map((tool) => tool.name),
    gateway_status: status.result.structuredContent.status,
    policy_denial: denied.result.structuredContent,
    registry_resource_bytes: registry.result.contents[0].text.length,
    preview: preview.result.structuredContent,
    send: sendResult,
    certificate_resource_bytes: certificate.result.contents[0].text.length,
    bundle: {
      version: bundle.version,
      receipt_count: bundle.receipts.length,
      has_keyring: Boolean(bundle.keyring),
      has_policy_decision: Boolean(bundle.policy_decision)
    },
    recipient_verification: recipientVerification.result.structuredContent
  }, null, 2));
} finally {
  for (const child of children.reverse()) {
    child.kill("SIGTERM");
  }
}

async function startWitnesses() {
  const urls = [];
  for (let index = 0; index < witnessPorts.length; index += 1) {
    const id = `w${index + 1}`;
    const port = witnessPorts[index];
    const child = spawn(process.execPath, [
      join(strataRoot, "bin", "turnstile-witness.js"),
      "--host", host,
      "--port", String(port),
      "--witness-id", id,
      "--key-file", join(dataDir, "witnesses", `${id}.key.json`),
      "--wal", join(dataDir, "witnesses", `${id}.wal.jsonl`)
    ], { stdio: ["ignore", "pipe", "pipe"] });
    children.push(child);
    child.stderr.on("data", (chunk) => process.stderr.write(chunk));
    const info = await waitForJsonLine(child.stdout);
    urls.push(`${id}=${info.url}`);
  }
  return urls.join(",");
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

async function startRegistry(witnessUrls, policyWitnessUrls) {
  const child = spawn(process.execPath, [join(root, "bin", "registry-server.js")], {
    cwd: root,
    env: {
      ...process.env,
      HOST: host,
      PORT: String(registryPort),
      DATA_DIR: dataDir,
      REGISTRY_KEY_FILE: join(dataDir, "registry", "registry-authority.key.json"),
      WITNESS_URLS: witnessUrls,
      POLICY_WITNESS_URLS: policyWitnessUrls
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  children.push(child);
  child.stderr.on("data", (chunk) => process.stderr.write(chunk));
  const info = await waitForJsonLine(child.stdout);
  return info.url;
}

function startServer(witnessUrls, policyWitnessUrls, registryUrl) {
  const env = {
    ...process.env,
    HOST: host,
    PORT: String(port),
    EMAIL_PROVIDER: process.env.EMAIL_PROVIDER || "dry-run",
    EMAIL_FROM: process.env.EMAIL_FROM || "strata-mcp@theforkproject.com",
    DATA_DIR: dataDir,
    PUBLIC_BASE_URL: `http://${host}:${port}`,
    CERTIFICATE_BASE_URL: `http://${host}:${port}/certificates`,
    WITNESS_URLS: witnessUrls,
    POLICY_WITNESS_URLS: policyWitnessUrls,
    REGISTRY_URL: registryUrl,
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

#!/usr/bin/env node
import { createServer } from "node:http";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { loadConfig } from "./config.js";
import { EmailMcpServer, MCP_PROTOCOL_VERSION } from "./mcp-server.js";
import { errorResponse, isNotification, parseJsonRpc, successResponse, validateRequest } from "./jsonrpc.js";
import { SessionManager } from "./session.js";
import { OAuthServer } from "./oauth/server.js";

const config = loadConfig();
const mcp = new EmailMcpServer(config);
const sessions = new SessionManager({ secret: config.sessionSecret });
const oauthServer = config.oauth.enabled ? new OAuthServer(config) : null;

if (config.sessionSecretWasGenerated) {
  console.warn("MCP_SESSION_SECRET not set; using an ephemeral development secret for this process.");
}

const server = createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/health") {
      return json(response, 200, {
        ok: true,
        name: "strata-email-mcp",
        email_provider: config.email.provider,
        witness_count: config.witnesses.length,
        oauth_enabled: Boolean(oauthServer)
      });
    }

    if (oauthServer?.canHandle(request)) {
      return oauthServer.handle(request, response);
    }

    if (request.method === "GET" && request.url?.startsWith("/certificates/")) {
      return serveCertificate(request, response);
    }

    if (request.url === "/mcp") {
      return handleMcp(request, response);
    }

    return json(response, 404, { error: "not found" });
  } catch (error) {
    return json(response, 500, { error: error.message });
  }
});

server.listen(config.port, config.host, () => {
  console.log(JSON.stringify({
    ok: true,
    url: `http://${config.host}:${config.port}`,
    mcp_url: `http://${config.host}:${config.port}/mcp`,
    email_provider: config.email.provider,
    witness_count: config.witnesses.length,
    oauth_enabled: Boolean(oauthServer)
  }, null, 2));
});

async function handleMcp(request, response) {
  setProtocolHeaders(response);
  setCorsHeaders(request, response);

  if (request.method === "OPTIONS") {
    response.writeHead(204);
    response.end();
    return;
  }

  if (request.method === "GET") {
    return json(response, 200, { name: "strata-email-mcp", version: "0.1.0" });
  }

  if (request.method === "DELETE") {
    response.writeHead(204);
    response.end();
    return;
  }

  if (request.method !== "POST") {
    return json(response, 405, { error: "method not allowed" });
  }

  const auth = authenticate(request);
  if (!auth.ok) {
    const authenticate = oauthServer
      ? `Bearer resource_metadata="${config.oauth.issuer}/.well-known/oauth-protected-resource", scope="mcp:read mcp:write"`
      : 'Bearer realm="strata-email-mcp", scope="mcp:read mcp:write"';
    response.writeHead(401, {
      "www-authenticate": authenticate
    });
    response.end("Unauthorized\n");
    return;
  }

  const contentType = request.headers["content-type"] || "";
  if (!contentType.startsWith("application/json")) {
    return json(response, 415, { error: "Content-Type must be application/json" });
  }

  const sessionId = auth.sessionId || sessions.createSession({ agentId: request.headers["x-agent-id"] || "mcp-client" });
  const raw = await readBody(request);
  let parsed;
  try {
    parsed = parseJsonRpc(raw);
  } catch (error) {
    return writeMcpJson(response, sessionId, errorResponse(null, error));
  }

  if (Array.isArray(parsed)) {
    const responses = [];
    for (const item of parsed) {
      const result = await handleSingle(item, auth.session);
      if (result) {
        responses.push(result);
      }
    }
    if (responses.length === 0) {
      response.writeHead(202, { "mcp-session-id": sessionId });
      response.end();
      return;
    }
    return writeMcpJson(response, sessionId, responses);
  }

  const result = await handleSingle(parsed, auth.session);
  if (!result) {
    response.writeHead(202, { "mcp-session-id": sessionId });
    response.end();
    return;
  }
  return writeMcpJson(response, sessionId, result);
}

async function handleSingle(request, session) {
  try {
    validateRequest(request);
    if (isNotification(request)) {
      return null;
    }
    const result = await mcp.dispatch(request, { session });
    return successResponse(request.id, result);
  } catch (error) {
    return errorResponse(request?.id ?? null, error);
  }
}

function authenticate(request) {
  const sessionId = request.headers["mcp-session-id"];
  const session = sessions.validateSession(sessionId);
  if (session) {
    return { ok: true, sessionId, session };
  }
  if (!config.bearerToken) {
    if (oauthServer) {
      const token = bearerToken(request);
      const accessToken = token ? oauthServer.validateAccessToken(token) : null;
      if (accessToken) {
        return { ok: true, session: { sid: accessToken.access_token.slice(-16), aid: accessToken.client_id, scope: accessToken.scope } };
      }
      return { ok: false };
    }
    return { ok: true, session: null };
  }
  const token = bearerToken(request);
  if (token === config.bearerToken) {
    return { ok: true, session: null };
  }
  if (oauthServer) {
    const accessToken = token ? oauthServer.validateAccessToken(token) : null;
    if (accessToken) {
      return { ok: true, session: { sid: accessToken.access_token.slice(-16), aid: accessToken.client_id, scope: accessToken.scope } };
    }
  }
  return { ok: false };
}

function bearerToken(request) {
  const header = request.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
}

function serveCertificate(request, response) {
  const url = new URL(request.url, config.publicBaseUrl);
  const parts = url.pathname.split("/").filter(Boolean);
  const runId = decodeURIComponent(parts[1] || "");
  if (!/^[a-zA-Z0-9_-]+$/.test(runId)) {
    return json(response, 400, { error: "invalid certificate id" });
  }
  const runDir = join(config.dataDir, "runs", runId);
  const certificatePath = join(runDir, "certificate.json");
  if (!existsSync(certificatePath)) {
    return json(response, 404, { error: "certificate not found" });
  }

  if (parts.length === 3 && parts[2] === "bundle") {
    return json(response, 200, loadCertificateBundle(runId, runDir));
  }

  if (parts.length === 4 && parts[2] === "artifacts") {
    return serveCertificateArtifact(response, runDir, parts[3]);
  }

  if (parts.length !== 2) {
    return json(response, 404, { error: "certificate route not found" });
  }

  response.writeHead(200, { "content-type": "application/json" });
  response.end(readFileSync(certificatePath, "utf8"));
}

function serveCertificateArtifact(response, runDir, artifactName) {
  const artifactMap = {
    "receipts.jsonl": { path: "receipts.jsonl", type: "application/jsonl" },
    "keyring.json": { path: "keyring.json", type: "application/json" },
    "checkpoint.json": { path: "checkpoint.json", type: "application/json" },
    "transparency-log.jsonl": { path: "transparency-log.jsonl", type: "application/jsonl" },
    "verification.json": { path: "verification.json", type: "application/json" },
    "policy-decision.json": { path: "policy-decision.json", type: "application/json" },
    "policy-bundle.json": { path: "policy-bundle.json", type: "application/json" },
    "registry-epoch.json": { path: "registry-epoch.json", type: "application/json" }
  };
  const artifact = artifactMap[artifactName];
  if (!artifact) {
    return json(response, 404, { error: "artifact not found" });
  }
  const artifactPath = join(runDir, artifact.path);
  if (!existsSync(artifactPath)) {
    return json(response, 404, { error: "artifact not found" });
  }
  response.writeHead(200, { "content-type": artifact.type });
  response.end(readFileSync(artifactPath, "utf8"));
}

function loadCertificateBundle(runId, runDir) {
  const certificate = readJson(join(runDir, "certificate.json"));
  return {
    version: "strata.email.certificate_bundle.v1",
    run_id: runId,
    bundle_url: `${config.certificateBaseUrl}/${runId}/bundle`,
    certificate,
    receipts: readJsonl(join(runDir, "receipts.jsonl")),
    keyring: readJson(join(runDir, "keyring.json")),
    checkpoint: readJson(join(runDir, "checkpoint.json")),
    transparency_log: readJsonl(join(runDir, "transparency-log.jsonl")),
    verification: readJson(join(runDir, "verification.json")),
    policy_decision: readOptionalJson(join(runDir, "policy-decision.json")),
    policy_bundle: readOptionalJson(join(runDir, "policy-bundle.json")),
    registry_epoch: readOptionalJson(join(runDir, "registry-epoch.json")),
    recipient_verifications: loadRecipientVerifications(certificate, runId)
  };
}

function loadRecipientVerifications(certificate, runId) {
  const dir = join(config.dataDir, "recipient-verifications");
  if (!existsSync(dir)) {
    return [];
  }
  return readdirSync(dir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => readOptionalJson(join(dir, file)))
    .filter(Boolean)
    .filter((receipt) => receipt.certificate_digest === certificate.certificate_digest || String(receipt.certificate_ref || "").includes(runId));
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function readOptionalJson(path) {
  if (!existsSync(path)) {
    return null;
  }
  return readJson(path);
}

function readJsonl(path) {
  if (!existsSync(path)) {
    return [];
  }
  return readFileSync(path, "utf8").split("\n").filter((line) => line.trim()).map((line) => JSON.parse(line));
}

function setProtocolHeaders(response) {
  response.setHeader("MCP-Protocol-Version", MCP_PROTOCOL_VERSION);
}

function setCorsHeaders(request, response) {
  const origin = request.headers.origin;
  if (!origin) {
    return;
  }
  if (config.allowedOrigins.length === 0 || config.allowedOrigins.includes(origin)) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Agent-ID, MCP-Session-Id");
    response.setHeader("Access-Control-Expose-Headers", "MCP-Session-Id, MCP-Protocol-Version");
  }
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function writeMcpJson(response, sessionId, body) {
  response.writeHead(200, {
    "content-type": "application/json",
    "mcp-session-id": sessionId,
    "mcp-protocol-version": MCP_PROTOCOL_VERSION
  });
  response.end(`${JSON.stringify(body)}\n`);
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

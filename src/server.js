#!/usr/bin/env node
import { createServer } from "node:http";
import { existsSync, readFileSync } from "node:fs";
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
  const runId = decodeURIComponent(request.url.slice("/certificates/".length).split("?")[0]);
  if (!/^[a-zA-Z0-9_-]+$/.test(runId)) {
    return json(response, 400, { error: "invalid certificate id" });
  }
  const path = join(config.dataDir, "runs", runId, "certificate.json");
  if (!existsSync(path)) {
    return json(response, 404, { error: "certificate not found" });
  }
  response.writeHead(200, { "content-type": "application/json" });
  response.end(readFileSync(path, "utf8"));
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

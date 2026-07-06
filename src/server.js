#!/usr/bin/env node
import { createServer } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { loadConfig } from "./config.js";
import { EmailMcpServer, MCP_PROTOCOL_VERSION } from "./mcp-server.js";
import { SupabaseMcpServer } from "./supabase-mcp-server.js";
import { KojimemMcpServer } from "./kojimem-mcp-server.js";
import { ManagedAgentPolicyGateway } from "./managed-agent-policy-gateway.js";
import { ResearchMcpServer } from "./research-mcp-server.js";
import { SharepointMcpServer } from "./sharepoint-mcp-server.js";
import { AttioMcpServer } from "./attio-mcp-server.js";
import { GmailMcpServer } from "./gmail-mcp-server.js";
import { GmailConnect } from "./gmail/connect.js";
import { errorResponse, isNotification, parseJsonRpc, successResponse, validateRequest } from "./jsonrpc.js";
import { SessionManager } from "./session.js";
import { OAuthServer } from "./oauth/server.js";
import { SupabaseConnectorOAuth } from "./supabase/connector-oauth.js";
import { NangoSupabaseConnect } from "./nango-supabase/connect.js";
import { loadCertificateBundle, loadRecipientVerifications } from "./certificates/bundle.js";

const config = loadConfig();
const mcp = config.gatewayKind === "research"
  ? new ResearchMcpServer(config)
  : config.gatewayKind === "gmail"
  ? new GmailMcpServer(config, { resolveClientName: async (clientId) => (await oauthServerRef()?.store?.getClient?.(clientId))?.client_name || null })
  : config.gatewayKind === "sharepoint"
  ? new SharepointMcpServer(config)
  : config.gatewayKind === "attio"
  ? new AttioMcpServer(config)
  : config.gatewayKind === "managed-agent-policy"
  ? new ManagedAgentPolicyGateway(config)
  : config.gatewayKind === "kojimem"
  ? new KojimemMcpServer(config)
  : config.gatewayKind === "supabase" || config.gatewayKind === "nango-supabase"
    ? new SupabaseMcpServer(config)
    : new EmailMcpServer(config);
const sessions = new SessionManager({ secret: config.sessionSecret });
const oauthServer = config.oauth.enabled ? new OAuthServer(config) : null;
function oauthServerRef() { return oauthServer; } // lazy: the Gmail server is constructed first
const gmailConnect = config.gatewayKind === "gmail" ? new GmailConnect(config) : null;
const supabaseConnectorOAuth = config.gatewayKind === "supabase" ? new SupabaseConnectorOAuth(config) : null;
const nangoSupabaseConnect = config.gatewayKind === "nango-supabase" ? new NangoSupabaseConnect(config) : null;

if (config.sessionSecretWasGenerated) {
  console.warn("MCP_SESSION_SECRET not set; using an ephemeral development secret for this process.");
}

const server = createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/health") {
      return json(response, 200, {
        ok: true,
        name: mcp.serverName,
        gateway_kind: config.gatewayKind,
        email_provider: config.gatewayKind === "email" ? config.email.provider : undefined,
        supabase_connector: config.gatewayKind === "supabase" ? {
          connector_id: config.supabase.connectorId,
          project_ref_configured: Boolean(config.supabase.projectRef),
          read_only: config.supabase.readOnly,
          features: config.supabase.features,
          upstream_calls_enabled: config.supabase.upstreamCallsEnabled
        } : undefined,
        research_connector: config.gatewayKind === "research" ? {
          assurance: config.research.assurance,
          xsearch_model: config.research.xsearchModel,
          vendors: {
            firecrawl: Boolean(config.research.firecrawlApiKey),
            perplexity: Boolean(config.research.perplexityApiKey),
            openrouter: Boolean(config.research.openrouterApiKey)
          }
        } : undefined,
        gmail_connector: config.gatewayKind === "gmail" ? {
          assurance: config.gmail.assurance,
          integration: config.gmail.providerConfigKey,
          nango_configured: Boolean(config.nango.secretKey),
          per_user_connections: true,
          fallback_connection_configured: Boolean(config.gmail.fallbackConnectionId)
        } : undefined,
        sharepoint_connector: config.gatewayKind === "sharepoint" ? {
          assurance: config.sharepoint.assurance,
          provider: config.sharepoint.providerConfigKey,
          connection_configured: Boolean(config.sharepoint.connectionId),
          nango_configured: Boolean(config.nango.secretKey),
          default_site: config.sharepoint.defaultSiteId
        } : undefined,
        kojimem_connector: config.gatewayKind === "kojimem" ? {
          connector_id: config.kojimem.connectorId,
          api_base_url: config.kojimem.apiBaseUrl,
          network: config.kojimem.network,
          agent_a_wallet_configured: Boolean(config.kojimem.agentAAccount?.address),
          agent_b_wallet_configured: Boolean(config.kojimem.agentBAccount?.address),
          l3_exposure_threshold_usd: config.kojimem.l3ExposureThresholdUsd
        } : undefined,
        witness_count: config.witnesses.length,
        ...(config.gatewayKind === "managed-agent-policy" ? await mcp.health() : {}),
        oauth_enabled: Boolean(oauthServer),
        oauth_store_backend: oauthServer ? config.oauth.storeBackend : "disabled"
      });
    }

    if (supabaseConnectorOAuth?.canHandle(request)) {
      return await supabaseConnectorOAuth.handle(request, response);
    }

    if (nangoSupabaseConnect?.canHandle(request)) {
      return await nangoSupabaseConnect.handle(request, response);
    }

    if (gmailConnect?.canHandle(request)) {
      return await gmailConnect.handle(request, response);
    }

    if (oauthServer?.canHandle(request)) {
      return await oauthServer.handle(request, response);
    }

    if (request.method === "GET" && request.url?.startsWith("/certificates/")) {
      return serveCertificate(request, response);
    }

    if (request.url === "/mcp") {
      return await handleMcp(request, response);
    }

    if (config.gatewayKind === "managed-agent-policy" && request.method === "POST" && request.url === "/v1/evaluate") {
      const body = await readBody(request).then((raw) => raw ? JSON.parse(raw) : {});
      return json(response, 200, await mcp.evaluate(body));
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
    name: mcp.serverName,
    gateway_kind: config.gatewayKind,
    email_provider: config.gatewayKind === "email" ? config.email.provider : undefined,
    witness_count: config.witnesses.length,
    oauth_enabled: Boolean(oauthServer),
    oauth_store_backend: oauthServer ? config.oauth.storeBackend : "disabled"
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
    return json(response, 200, { name: mcp.serverName, version: "0.1.0" });
  }

  if (request.method === "DELETE") {
    response.writeHead(204);
    response.end();
    return;
  }

  if (request.method !== "POST") {
    return json(response, 405, { error: "method not allowed" });
  }

  const auth = await authenticate(request);
  if (!auth.ok) {
      const authenticate = oauthServer
        ? `Bearer resource_metadata="${config.oauth.issuer}/.well-known/oauth-protected-resource", scope="mcp:read mcp:write"`
        : `Bearer realm="${mcp.serverName}", scope="mcp:read mcp:write"`;
    response.writeHead(401, {
      "www-authenticate": authenticate
    });
    response.end("Unauthorized\n");
    return;
  }

  const contentType = request.headers["content-type"] || "";
  if (contentType && !contentType.startsWith("application/json") && !contentType.startsWith("text/plain")) {
    return json(response, 415, { error: "Content-Type must be application/json" });
  }

  /* Preserve OAuth identity across the session handshake: the first request
     authenticates with a Bearer token (aid = oauth client_id), and every
     subsequent request rides the mcp-session-id token — which must CARRY that
     identity or per-caller resolution (e.g. the Gmail gateway's subject →
     Nango connection mapping) silently degrades to "mcp-client". */
  const sessionId = auth.sessionId || sessions.createSession({ agentId: auth.session?.aid || request.headers["x-agent-id"] || "mcp-client", tenantId: config.tenant.id });
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

async function authenticate(request) {
  const sessionId = request.headers["mcp-session-id"];
  const session = sessions.validateSession(sessionId);
  if (session) {
    return { ok: true, sessionId, session };
  }
  if (!config.bearerToken) {
    if (oauthServer) {
      const token = bearerToken(request);
      const accessToken = token ? await oauthServer.validateAccessToken(token) : null;
      if (accessToken) {
        return { ok: true, session: oauthSession(accessToken) };
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
    const accessToken = token ? await oauthServer.validateAccessToken(token) : null;
    if (accessToken) {
      return { ok: true, session: oauthSession(accessToken) };
    }
  }
  return { ok: false };
}

function oauthSession(accessToken) {
  return {
    sid: accessToken.access_token.slice(-16),
    aid: accessToken.client_id,
    tid: config.tenant.id,
    scope: accessToken.scope,
    auth_method: "oauth"
  };
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
    const certificate = readJson(certificatePath);
    return json(response, 200, loadCertificateBundle({
      config,
      runId,
      runDir,
      recipientVerifications: loadRecipientVerifications({ config, certificate, runId })
    }));
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
    "admission-manifest.json": { path: "admission-manifest.json", type: "application/json" },
    "operator-registry.json": { path: "operator-registry.json", type: "application/json" },
    "policy-decision.json": { path: "policy-decision.json", type: "application/json" },
    "policy-bundle.json": { path: "policy-bundle.json", type: "application/json" },
    "registry-epoch.json": { path: "registry-epoch.json", type: "application/json" },
    "gateway-attestation.json": { path: "gateway-attestation.json", type: "application/json" },
    "l1-witness-attestations.json": { path: "l1-witness-attestations.json", type: "application/json" },
    "connector-manifest.json": { path: "connector-manifest.json", type: "application/json" },
    "supabase-request.json": { path: "supabase-request.json", type: "application/json" },
    "supabase-result-metadata.json": { path: "supabase-result-metadata.json", type: "application/json" },
    "kojimem-request.json": { path: "kojimem-request.json", type: "application/json" },
    "kojimem-result-metadata.json": { path: "kojimem-result-metadata.json", type: "application/json" }
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

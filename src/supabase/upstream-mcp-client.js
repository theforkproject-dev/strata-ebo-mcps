import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { upstreamMcpUrl } from "./canonical.js";

export class SupabaseMcpClient {
  constructor(config, { fetchImpl = fetch } = {}) {
    this.config = config;
    this.fetchImpl = fetchImpl;
    this.sessionId = "";
    this.nextId = 1;
  }

  async listTools() {
    await this.initialize();
    return this.rpc("tools/list", {});
  }

  async callTool(name, args = {}) {
    await this.initialize();
    return this.rpc("tools/call", { name, arguments: args });
  }

  async initialize() {
    if (this.sessionId) {
      return;
    }
    try {
      await this.rpc("initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: {
          name: "strata-supabase-mcp-gateway",
          version: "0.1.0"
        }
      });
    } catch (error) {
      if (!String(error.message || "").includes("Method not found")) {
        throw error;
      }
    }
  }

  async rpc(method, params) {
    const credential = await loadSupabaseConnectorCredential(this.config);
    const accessToken = credential.access_token || this.config.supabase.oauth.accessToken;
    if (!accessToken) {
      throw new Error("Supabase connector is not authorized; complete /connectors/supabase/oauth/start or set SUPABASE_OAUTH_ACCESS_TOKEN");
    }

    const response = await this.fetchImpl(upstreamMcpUrl(this.config), {
      method: "POST",
      headers: {
        "accept": "application/json, text/event-stream",
        "authorization": `Bearer ${accessToken}`,
        "content-type": "application/json",
        "mcp-protocol-version": "2025-11-25",
        ...(this.sessionId ? { "mcp-session-id": this.sessionId } : {})
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: this.nextId++,
        method,
        params
      })
    });

    const returnedSessionId = response.headers.get("mcp-session-id");
    if (returnedSessionId) {
      this.sessionId = returnedSessionId;
    }
    const body = await readMcpBody(response);
    if (!response.ok) {
      throw new Error(body?.error?.message || body?.error || `Supabase MCP returned ${response.status}`);
    }
    if (body?.error) {
      throw new Error(body.error.message || JSON.stringify(body.error));
    }
    return body?.result ?? body;
  }
}

export async function loadSupabaseConnectorCredential(config) {
  const fromFile = readCredentialFile(config.supabase.oauth.storePath);
  return {
    access_token: config.supabase.oauth.accessToken || fromFile?.access_token || "",
    refresh_token: config.supabase.oauth.refreshToken || fromFile?.refresh_token || "",
    token_type: fromFile?.token_type || "Bearer",
    expires_at: fromFile?.expires_at || null,
    scope: fromFile?.scope || config.supabase.oauth.scope || ""
  };
}

export async function refreshSupabaseConnectorCredential(config, { fetchImpl = fetch } = {}) {
  const existing = await loadSupabaseConnectorCredential(config);
  const refreshToken = existing.refresh_token;
  const tokenUrl = config.supabase.oauth.tokenUrl;
  if (!refreshToken) {
    throw new Error("SUPABASE_OAUTH_REFRESH_TOKEN or connector credential refresh_token is required");
  }
  if (!tokenUrl) {
    throw new Error("SUPABASE_OAUTH_TOKEN_URL is required to refresh Supabase connector credentials");
  }
  const form = new URLSearchParams();
  form.set("grant_type", "refresh_token");
  form.set("refresh_token", refreshToken);
  const tokenAuth = tokenEndpointAuth(config, form);
  const response = await fetchImpl(tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...tokenAuth.headers },
    body: form
  });
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body.error_description || body.error || `Supabase token refresh returned ${response.status}`);
  }
  const credential = normalizeTokenResponse(body);
  writeSupabaseConnectorCredential(config, credential);
  return credential;
}

export function writeSupabaseConnectorCredential(config, tokenResponse) {
  const credential = normalizeTokenResponse(tokenResponse);
  mkdirSync(dirname(config.supabase.oauth.storePath), { recursive: true });
  writeFileSync(config.supabase.oauth.storePath, `${JSON.stringify({
    version: "strata.supabase.connector_credential.v1",
    saved_at: new Date().toISOString(),
    ...credential
  }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  return credential;
}

function normalizeTokenResponse(body) {
  const expiresIn = Number(body.expires_in || 0);
  return {
    access_token: body.access_token || "",
    refresh_token: body.refresh_token || "",
    token_type: body.token_type || "Bearer",
    scope: body.scope || "",
    expires_at: expiresIn ? Date.now() + expiresIn * 1000 : null
  };
}

function tokenEndpointAuth(config, form) {
  const method = config.supabase.oauth.tokenAuthMethod || "client_secret_basic";
  if (method === "client_secret_basic") {
    const raw = `${encodeURIComponent(config.supabase.oauth.clientId)}:${encodeURIComponent(config.supabase.oauth.clientSecret)}`;
    return { headers: { authorization: `Basic ${Buffer.from(raw).toString("base64")}` } };
  }
  form.set("client_id", config.supabase.oauth.clientId);
  if (method === "client_secret_post" && config.supabase.oauth.clientSecret) {
    form.set("client_secret", config.supabase.oauth.clientSecret);
  }
  return { headers: {} };
}

function readCredentialFile(path) {
  if (!path || !existsSync(path)) {
    return null;
  }
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  return parsed && typeof parsed === "object" ? parsed : null;
}

async function readMcpBody(response) {
  const raw = await response.text();
  if (!raw.trim()) {
    return null;
  }
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("text/event-stream")) {
    return parseSseJson(raw);
  }
  return JSON.parse(raw);
}

function parseSseJson(raw) {
  const dataLines = raw.split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice("data:".length).trim())
    .filter((line) => line && line !== "[DONE]");
  if (dataLines.length === 0) {
    return null;
  }
  return JSON.parse(dataLines[dataLines.length - 1]);
}

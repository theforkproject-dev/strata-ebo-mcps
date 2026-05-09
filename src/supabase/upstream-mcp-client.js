import { createConnectorCredentialStore } from "../connectors/credential-store.js";
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
      await this.notify("notifications/initialized", {});
    } catch (error) {
      if (!String(error.message || "").includes("Method not found")) {
        throw error;
      }
    }
  }

  async rpc(method, params) {
    return this.sendJsonRpc({
      jsonrpc: "2.0",
      id: this.nextId++,
      method,
      params
    }, { expectResult: true });
  }

  async notify(method, params) {
    await this.sendJsonRpc({ jsonrpc: "2.0", method, params }, { expectResult: false });
  }

  async sendJsonRpc(payload, { expectResult }) {
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
      body: JSON.stringify(payload)
    });

    const returnedSessionId = response.headers.get("mcp-session-id");
    if (returnedSessionId) {
      this.sessionId = returnedSessionId;
    }
    const body = await readMcpBody(response);
    if (!response.ok) {
      throw new Error(upstreamHttpError(response.status, body));
    }
    if (body?.error) {
      throw new Error(body.error.message || JSON.stringify(body.error));
    }
    if (!expectResult) {
      return null;
    }
    return body?.result ?? body;
  }
}

export async function loadSupabaseConnectorCredential(config) {
  if (config.supabase.oauth.accessToken || config.supabase.oauth.refreshToken) {
    return {
      access_token: config.supabase.oauth.accessToken || "",
      refresh_token: config.supabase.oauth.refreshToken || "",
      token_type: "Bearer",
      expires_at: null,
      scope: config.supabase.oauth.scope || ""
    };
  }
  const store = createConnectorCredentialStore(config);
  const fromStore = await store.get(supabaseConnectorScope(config));
  return {
    access_token: fromStore?.access_token || "",
    refresh_token: fromStore?.refresh_token || "",
    token_type: fromStore?.token_type || "Bearer",
    expires_at: fromStore?.expires_at || null,
    scope: fromStore?.scope || config.supabase.oauth.scope || "",
    credential_fingerprint: fromStore?.credential_fingerprint || null,
    saved_at: fromStore?.saved_at || null
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
  if (config.supabase.oauth.resource) {
    form.set("resource", config.supabase.oauth.resource);
  }
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
  await writeSupabaseConnectorCredential(config, credential);
  return credential;
}

export async function writeSupabaseConnectorCredential(config, tokenResponse) {
  const credential = normalizeTokenResponse(tokenResponse);
  const store = createConnectorCredentialStore(config);
  return store.put(supabaseConnectorScope(config), credential, {
    upstream_url: upstreamMcpUrl(config),
    read_only: config.supabase.readOnly,
    features: config.supabase.features,
    auth_mode: "supabase_manual_oauth_app"
  });
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

function upstreamHttpError(status, body) {
  const details = body ? JSON.stringify(body) : "";
  return details ? `Supabase MCP returned ${status}: ${details}` : `Supabase MCP returned ${status}`;
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

function supabaseConnectorScope(config) {
  return {
    tenantId: config.tenant.id,
    connectorType: "supabase_mcp",
    connectorId: config.supabase.connectorId,
    subject: "default"
  };
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

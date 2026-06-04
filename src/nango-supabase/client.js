import { digestValue } from "../strata/primitives.js";

export function nangoSupabaseConfigured(config) {
  return Boolean(config.nango?.secretKey && config.nangoSupabase?.providerConfigKey);
}

export function nangoSupabaseConnectUrl(config, requestContext = {}) {
  const base = config.publicBaseUrl.replace(/\/$/, "");
  const url = new URL(`${base}/connectors/nango/supabase/start`);
  const tags = nangoSupabaseTags(config, requestContext);
  for (const [key, value] of Object.entries(tags)) {
    if (value) url.searchParams.set(key, value);
  }
  return url.toString();
}

export function nangoSupabaseTags(config, requestContext = {}) {
  const session = requestContext.session || {};
  return {
    end_user_id: session.aid || config.nangoSupabase.endUserId,
    end_user_email: config.nangoSupabase.endUserEmail,
    organization_id: session.tid || config.nangoSupabase.organizationId,
    attexa_poc: config.nangoSupabase.tag,
    gateway_kind: "nango-supabase"
  };
}

export async function createNangoSupabaseConnectSession(config, { tags = nangoSupabaseTags(config) } = {}) {
  requireNangoSupabaseConfig(config);
  const body = await nangoApi(config, "/connect/sessions", {
    method: "POST",
    body: {
      allowed_integrations: [config.nangoSupabase.providerConfigKey],
      tags
    }
  });
  const data = body.data || body;
  return {
    connect_link: data.connect_link || data.connectLink || data.link || null,
    expires_at: data.expires_at || data.expiresAt || null,
    tags
  };
}

export async function resolveNangoSupabaseConnection(config, requestContext = {}, { fetchImpl = fetch } = {}) {
  if (!nangoSupabaseConfigured(config)) {
    return missingConnection(config, requestContext, ["NANGO_SECRET_KEY", "NANGO_SUPABASE_PROVIDER_CONFIG_KEY"]);
  }

  if (config.nangoSupabase.connectionId) {
    try {
      const connection = await getNangoSupabaseConnection(config, config.nangoSupabase.connectionId, { fetchImpl });
      return connectionBinding(config, connection, requestContext);
    } catch (error) {
      return missingConnection(config, requestContext, [error.message]);
    }
  }

  try {
    const tags = nangoSupabaseTags(config, requestContext);
    const connections = await listNangoSupabaseConnections(config, tags, { fetchImpl });
    const connection = connections[0] || null;
    if (!connection) {
      return missingConnection(config, requestContext, []);
    }
    return connectionBinding(config, connection, requestContext);
  } catch (error) {
    return missingConnection(config, requestContext, [error.message]);
  }
}

export async function listNangoSupabaseConnections(config, tags = nangoSupabaseTags(config), { fetchImpl = fetch } = {}) {
  requireNangoSupabaseConfig(config);
  const url = new URL("/connections", config.nango.serverUrl);
  url.searchParams.set("integrationId", config.nangoSupabase.providerConfigKey);
  for (const [key, value] of Object.entries(tags)) {
    if (value) url.searchParams.set(`tags[${key}]`, value);
  }
  const body = await nangoApi(config, `${url.pathname}${url.search}`, { fetchImpl });
  return Array.isArray(body) ? body : body.connections || body.data || [];
}

export async function getNangoSupabaseConnection(config, connectionId, { fetchImpl = fetch } = {}) {
  requireNangoSupabaseConfig(config);
  const path = `/connections/${encodeURIComponent(connectionId)}?provider_config_key=${encodeURIComponent(config.nangoSupabase.providerConfigKey)}`;
  const body = await nangoApi(config, path, { fetchImpl });
  return body.connection || body.data || body;
}

export async function nangoMcpJsonRpc(config, connectionId, payload, { projectRef = "", mcpSessionId = "", onSession = null, fetchImpl = fetch } = {}) {
  requireNangoSupabaseConfig(config);
  if (!connectionId) {
    throw new Error("Nango Supabase connection is required");
  }
  const url = new URL(`${config.nango.serverUrl}/proxy/mcp`);
  const effectiveProjectRef = projectRef || config.nangoSupabase.projectRef || config.supabase.projectRef || "";
  if (effectiveProjectRef) {
    url.searchParams.set("project_ref", effectiveProjectRef);
  }
  const response = await fetchImpl(url.toString(), {
    method: "POST",
    headers: {
      "accept": "application/json, text/event-stream",
      "authorization": `Bearer ${config.nango.secretKey}`,
      "content-type": "application/json",
      "nango-proxy-mcp-protocol-version": "2025-11-25",
      "provider-config-key": config.nangoSupabase.providerConfigKey,
      "connection-id": connectionId,
      ...(mcpSessionId ? { "nango-proxy-mcp-session-id": mcpSessionId } : {})
    },
    body: JSON.stringify(payload)
  });
  const returnedSession = response.headers.get("mcp-session-id");
  if (returnedSession && onSession) {
    onSession(returnedSession);
  }
  const body = await readNangoBody(response);
  if (!response.ok) {
    throw new Error(nangoHttpError(response.status, body));
  }
  if (body?.error) {
    throw new Error(body.error.message || JSON.stringify(body.error));
  }
  return body?.result ?? body;
}

export function nangoConnectionFingerprint(binding = {}) {
  const source = binding.connection_id || binding.connectionId || "";
  return source ? `sha256:${digestValue({ nango_connection_id: source })}` : null;
}

function connectionBinding(config, connection, requestContext) {
  const connectionId = connection.connection_id || connection.connectionId || connection.id || config.nangoSupabase.connectionId || "";
  const projectRef = extractProjectRef(connection) || config.nangoSupabase.projectRef || config.supabase.projectRef || "";
  return {
    ok: Boolean(connectionId),
    connection,
    connection_id: connectionId,
    provider_config_key: config.nangoSupabase.providerConfigKey,
    project_ref: projectRef,
    credential_fingerprint: nangoConnectionFingerprint({ connection_id: connectionId }),
    connect_url: nangoSupabaseConnectUrl(config, requestContext),
    missing: []
  };
}

function missingConnection(config, requestContext, missing) {
  return {
    ok: false,
    connection: null,
    connection_id: "",
    provider_config_key: config.nangoSupabase?.providerConfigKey || "",
    project_ref: config.nangoSupabase?.projectRef || config.supabase?.projectRef || "",
    credential_fingerprint: null,
    connect_url: nangoSupabaseConnectUrl(config, requestContext),
    missing
  };
}

function extractProjectRef(connection) {
  const candidates = [
    connection?.connection_config?.project_ref,
    connection?.connection_config?.projectRef,
    connection?.connectionConfig?.project_ref,
    connection?.connectionConfig?.projectRef,
    connection?.metadata?.project_ref,
    connection?.metadata?.projectRef,
    connection?.credentials?.project_ref,
    connection?.credentials?.projectRef
  ];
  return candidates.find(Boolean) || "";
}

async function nangoApi(config, path, { method = "GET", body = null, fetchImpl = fetch } = {}) {
  requireNangoSupabaseConfig(config);
  const response = await fetchImpl(`${config.nango.serverUrl}${path}`, {
    method,
    headers: {
      "authorization": `Bearer ${config.nango.secretKey}`,
      ...(body ? { "content-type": "application/json" } : {})
    },
    ...(body ? { body: JSON.stringify(body) } : {})
  });
  const text = await response.text();
  const parsed = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(`Nango API returned ${response.status}: ${summarizeNangoError(parsed)}`);
  }
  return parsed;
}

function requireNangoSupabaseConfig(config) {
  if (!config.nango?.secretKey) {
    throw new Error("NANGO_SECRET_KEY is required");
  }
  if (!config.nangoSupabase?.providerConfigKey) {
    throw new Error("NANGO_SUPABASE_PROVIDER_CONFIG_KEY is required");
  }
}

async function readNangoBody(response) {
  const raw = await response.text();
  if (!raw.trim()) return null;
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
  if (dataLines.length === 0) return null;
  return JSON.parse(dataLines[dataLines.length - 1]);
}

function nangoHttpError(status, body) {
  const details = summarizeNangoError(body);
  return details ? `Nango MCP returned ${status}: ${details}` : `Nango MCP returned ${status}`;
}

function summarizeNangoError(body) {
  if (!body) return "";
  if (typeof body === "string") return body.slice(0, 500);
  const redacted = JSON.stringify(body, (key, value) => key.toLowerCase().includes("token") ? "[redacted]" : value);
  return redacted.slice(0, 500);
}

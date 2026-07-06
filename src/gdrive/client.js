/**
 * Nango client for the Google Drive gateway (integration-lanes.md Lane 2,
 * manifest #4 — mirrors src/gmail/client.js).
 *
 * Nango is the EXECUTION BACKEND, never agent-facing: the environment secret
 * key lives here and only here; agents authenticate to THIS gateway with
 * per-mint OAuth credentials whose client_name carries the caller's subject
 * (`aa:<org>:<userId>`), and the gateway resolves subject → Nango connection.
 * Per-user custody, one hop from the thesis: the credential is the boundary.
 */

const CONNECTION_CACHE_TTL_MS = 60 * 1000;
const connectionCache = new Map();

export function gdriveConfigured(config) {
  return Boolean(config.nango.secretKey && config.gdrive.providerConfigKey);
}

function nangoHeaders(config) {
  return {
    authorization: `Bearer ${config.nango.secretKey}`,
    "content-type": "application/json"
  };
}

/**
 * Resolve the caller's Drive connection: exact end_user.id match on the
 * google-drive integration, tiny TTL cache, env fallback for an org-level
 * demo connection. Returns null when the subject has never connected.
 */
export async function resolveGdriveConnection(config, subject, { fetchImpl = fetch } = {}) {
  const key = String(subject || "").trim() || "unknown";
  const cached = connectionCache.get(key);
  if (cached && Date.now() - cached.at < CONNECTION_CACHE_TTL_MS) return cached.connectionId;

  /* No server-side filter — Nango's list endpoint 400s on the param in this
     environment; filter client-side by integration + exact end_user id. */
  const response = await fetchImpl(`${config.nango.serverUrl}/connection`, { headers: nangoHeaders(config) });
  if (!response.ok) throw new Error(`Nango connection list failed (${response.status})`);
  const body = await response.json();
  const connections = (body.connections || []).filter(
    (connection) => connection.provider_config_key === config.gdrive.providerConfigKey
  );
  const match = connections.find((connection) => connection.end_user?.id === key);
  const connectionId = match?.connection_id || config.gdrive.fallbackConnectionId || null;
  if (connectionId) connectionCache.set(key, { connectionId, at: Date.now() });
  return connectionId;
}

/** Create a Nango connect session and return the hosted-auth link. */
export async function createGdriveConnectSession(config, { endUserId, email = "", displayName = "" }, { fetchImpl = fetch } = {}) {
  const response = await fetchImpl(`${config.nango.serverUrl}/connect/sessions`, {
    method: "POST",
    headers: nangoHeaders(config),
    body: JSON.stringify({
      end_user: {
        id: endUserId,
        ...(email ? { email } : {}),
        ...(displayName ? { display_name: displayName } : {})
      },
      allowed_integrations: [config.gdrive.providerConfigKey]
    })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`Nango connect session failed (${response.status}): ${data?.message || "unknown"}`);
  }
  return { connectLink: data.data?.connect_link || null };
}

/**
 * Call the Google Drive REST API through Nango's authenticated proxy for a
 * specific connection. Path is the Drive API path (e.g. /drive/v3/files).
 * `raw: true` returns the body as text (media downloads / exports) instead
 * of parsed JSON.
 */
export async function gdriveProxy(config, { connectionId, method = "GET", path, query = null, body = null, raw = false }, { fetchImpl = fetch } = {}) {
  const url = new URL(`${config.nango.serverUrl}/proxy${path}`);
  for (const [k, v] of Object.entries(query || {})) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.gdrive.timeoutMs);
  try {
    const response = await fetchImpl(url, {
      method,
      headers: {
        ...nangoHeaders(config),
        "connection-id": connectionId,
        "provider-config-key": config.gdrive.providerConfigKey
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: controller.signal
    });
    if (raw) {
      const text = await response.text().catch(() => "");
      return { ok: response.ok, status: response.status, text };
    }
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, data };
  } finally {
    clearTimeout(timer);
  }
}

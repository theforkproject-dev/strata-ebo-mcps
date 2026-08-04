/**
 * Nango client for the Gmail gateway (integration-lanes.md Lane 2).
 *
 * Nango is the EXECUTION BACKEND, never agent-facing: the environment secret
 * key lives here and only here; agents authenticate to THIS gateway with
 * per-mint OAuth credentials whose client_name carries the caller's subject
 * (`aa:<org>:<userId>`), and the gateway resolves subject → Nango connection.
 * Per-user custody, one hop from the thesis: the credential is the boundary.
 */

const CONNECTION_CACHE_TTL_MS = 60 * 1000;
const connectionCache = new Map(); // subject → { connectionId, at }

export function gmailConfigured(config) {
  return Boolean(config.nango.secretKey && config.gmail.providerConfigKey);
}

function nangoHeaders(config) {
  return {
    authorization: `Bearer ${config.nango.secretKey}`,
    "content-type": "application/json"
  };
}

async function gmailConnectionWorks(config, connectionId, { fetchImpl = fetch } = {}) {
  if (!connectionId) return false;
  try {
    const response = await fetchImpl(`${config.nango.serverUrl}/proxy/gmail/v1/users/me/profile`, {
      headers: {
        ...nangoHeaders(config),
        "connection-id": connectionId,
        "provider-config-key": config.gmail.providerConfigKey
      },
      signal: AbortSignal.timeout(config.gmail.timeoutMs || 10_000)
    });
    await response.body?.cancel?.().catch(() => {});
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Resolve the caller's Gmail connection: exact end_user.id match on the
 * google-mail integration, tiny TTL cache, env fallback for an org-level demo
 * connection. Returns null when the subject has never connected or its exact
 * connection has a terminal authentication error.
 */
export async function getGmailConnectionState(config, subject, { fetchImpl = fetch } = {}) {
  const key = String(subject || "").trim() || "unknown";
  /* No server-side filter — Nango's list endpoint 400s on the param in this
     environment; filter client-side by integration + exact end_user id. */
  const response = await fetchImpl(`${config.nango.serverUrl}/connection`, { headers: nangoHeaders(config) });
  if (!response.ok) throw new Error(`Nango connection list failed (${response.status})`);
  const body = await response.json();
  const connections = (body.connections || []).filter(
    (connection) => connection.provider_config_key === config.gmail.providerConfigKey
  );
  const match = connections.find((connection) => connection.end_user?.id === key);
  /* Nango retains broken connection rows after refresh credentials become
     terminally invalid. Fail closed, and never fall through to an org demo
     connection when an exact user's connection exists but is broken. */
  const recordedAuthFailure = match?.errors?.some((error) => error?.type === "auth");
  /* Nango retains historical auth errors after a connection has recovered.
     Require a current provider canary to fail before asking the user to
     reauthorize; a stale error beside a working connection remains ready. */
  const authFailed = recordedAuthFailure && !(await gmailConnectionWorks(config, match?.connection_id, { fetchImpl }));
  const connectionId = match
    ? (authFailed ? null : match.connection_id)
    : config.gmail.fallbackConnectionId || null;
  return {
    status: authFailed ? "reconnect_required" : connectionId ? "ready" : "connection_required",
    connectionId,
    existingConnectionId: match?.connection_id || null
  };
}

export async function resolveGmailConnection(config, subject, { fetchImpl = fetch } = {}) {
  const key = String(subject || "").trim() || "unknown";
  const cached = connectionCache.get(key);
  if (cached && Date.now() - cached.at < CONNECTION_CACHE_TTL_MS) return cached.connectionId;
  const { connectionId } = await getGmailConnectionState(config, key, { fetchImpl });
  if (connectionId) connectionCache.set(key, { connectionId, at: Date.now() });
  return connectionId;
}

/** Create a Nango Connect session for a subject; returns the hosted connect link. */
export async function createGmailConnectSession(config, { endUserId, email = "", displayName = "", connectionId = null }, { fetchImpl = fetch } = {}) {
  const reconnect = Boolean(connectionId);
  const response = await fetchImpl(`${config.nango.serverUrl}/connect/sessions${reconnect ? "/reconnect" : ""}`, {
    method: "POST",
    headers: nangoHeaders(config),
    body: JSON.stringify(reconnect
      ? { connection_id: connectionId, integration_id: config.gmail.providerConfigKey }
      : {
          end_user: {
            id: String(endUserId),
            ...(email ? { email } : {}),
            ...(displayName ? { display_name: displayName } : {})
          },
          allowed_integrations: [config.gmail.providerConfigKey]
        })
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`Nango connect session failed (${response.status}): ${JSON.stringify(body).slice(0, 200)}`);
  }
  const data = body.data || body;
  return { connectLink: data.connect_link || data.connect_url || null, token: data.token || null };
}

/**
 * Call the Gmail REST API through Nango's authenticated proxy for a specific
 * connection. Path is the Gmail API path (e.g. /gmail/v1/users/me/messages).
 */
export async function gmailProxy(config, { connectionId, method = "GET", path, query = null, body = null }, { fetchImpl = fetch } = {}) {
  const url = new URL(`${config.nango.serverUrl}/proxy${path}`);
  for (const [k, v] of Object.entries(query || {})) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.gmail.timeoutMs);
  try {
    const response = await fetchImpl(url, {
      method,
      headers: {
        ...nangoHeaders(config),
        "connection-id": connectionId,
        "provider-config-key": config.gmail.providerConfigKey
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: controller.signal
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, data };
  } finally {
    clearTimeout(timer);
  }
}

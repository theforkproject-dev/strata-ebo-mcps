/* Shared per-user Google custody. Nango is server-side only; a model never
 * chooses a Nango connection, integration, token, or upstream origin. */
export class GoogleConnectionError extends Error {
  constructor(code, status = 503) {
    super(code === "google_pilot_pending" ? "Your account is not enabled for this Google pilot. Ask your workspace administrator." : code);
    this.code = code; this.status = status;
  }
}

const PROVIDERS = { gmail: "google-mail", gdrive: "google-drive", gcalendar: "google-calendar" };
const SCOPE_PREFIX = "https://www.googleapis.com/auth/";
const SCOPES = { gmail: ["gmail.readonly", "userinfo.email"], gdrive: ["drive.readonly", "userinfo.email"],
  gcalendar: ["calendar.calendarlist.readonly", "calendar.events.readonly", "calendar.events.freebusy", "userinfo.email"] };
const READ_SCOPES = new Set(["openid", ...Object.values(SCOPES).flat().map((scope) => SCOPE_PREFIX + scope)]);

export function googleSubject(config, value) {
  const org = config.googleConnect?.orgId;
  if (!org || !/^[A-Za-z0-9_-]{1,100}$/.test(org)) throw new GoogleConnectionError("google_tenant_not_configured");
  if (typeof value !== "string" || !value.startsWith(`aa:${org}:`)
      || !/^aa:[A-Za-z0-9_-]{1,100}:usr_[A-Za-z0-9_-]{1,128}$/.test(value)) {
    throw new GoogleConnectionError("google_subject_forbidden", 403);
  }
  return value;
}

export function googleProfile(config, kind, subject) {
  googleSubject(config, subject);
  const service = config[kind];
  if (!PROVIDERS[kind] || !googleConfigured(config, kind)) throw new GoogleConnectionError("google_not_configured");
  const pilots = config.googleConnect.pilotSubjects || [];
  const central = !pilots.length || pilots.includes(subject);
  if (!central && !service.legacyProviderConfigKey) return null;
  return { ...service, provider: PROVIDERS[kind], integrationId: central ? service.providerConfigKey : service.legacyProviderConfigKey,
    central, testingMode: central && config.googleConnect.testingMode === true };
}

export function googleConfigured(config, kind) {
  const org = config.googleConnect?.orgId, service = config[kind];
  const keyPattern = /^[A-Za-z0-9_-]{1,200}$/;
  return Boolean(PROVIDERS[kind] && config.nango?.secretKey && /^[A-Za-z0-9_-]{1,100}$/.test(org || "")
    && keyPattern.test(service?.providerConfigKey || "")
    && (!service.legacyProviderConfigKey || (keyPattern.test(service.legacyProviderConfigKey)
      && service.legacyProviderConfigKey !== service.providerConfigKey && config.googleConnect.pilotSubjects?.length > 0))
    && Array.isArray(config.googleConnect.pilotSubjects || [])
    && (config.googleConnect.pilotSubjects || []).every((value) => {
      try { return googleSubject(config, value) === value; } catch { return false; }
    }));
}

function headers(config) {
  return { Authorization: `Bearer ${config.nango.secretKey}`, "Content-Type": "application/json" };
}

async function nangoJson(config, path, { fetchImpl = fetch, method = "GET", body } = {}) {
  let response;
  try {
    response = await fetchImpl(`${config.nango.serverUrl}${path}`, { method, redirect: "error",
      headers: headers(config), ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(20000) });
  } catch { throw new GoogleConnectionError("google_connection_service_unavailable"); }
  if (!response.ok) throw new GoogleConnectionError("google_connection_service_unavailable");
  try { return await response.json(); }
  catch { throw new GoogleConnectionError("google_connection_response_invalid"); }
}

/** Bounded complete inventory; pagination is zero-based. Legacy and tagged
 * records are examined together so conflicting/duplicate ownership fails closed. */
export async function googleConnectionRows(config, { fetchImpl = fetch } = {}) {
  const rows = [];
  for (let page = 0; page < 10; page++) {
    const body = await nangoJson(config, `/connections?limit=100&page=${page}`, { fetchImpl });
    if (!Array.isArray(body.connections)) throw new GoogleConnectionError("google_connection_response_invalid");
    rows.push(...body.connections);
    if (body.connections.length < 100) return rows;
  }
  throw new GoogleConnectionError("google_connection_inventory_incomplete");
}

export function selectGoogleConnection(rows, { subject, orgId, integrationId, provider, allowLegacy = false }) {
  const matches = [];
  for (const row of rows) {
    if (row.provider_config_key !== integrationId) continue;
    const tagged = row.tags?.end_user_id;
    const legacy = row.end_user?.id;
    if (tagged !== subject && legacy !== subject) continue;
    if (row.provider !== provider || (tagged != null && tagged !== subject) || (legacy != null && legacy !== subject)
        || (tagged == null && !allowLegacy)
        || (tagged != null && row.tags?.organization_id !== orgId
          && !(allowLegacy && row.tags?.organization_id == null && legacy === subject))
        || (row.end_user?.organization?.id != null && row.end_user.organization.id !== orgId)
        || typeof row.connection_id !== "string" || !row.connection_id) {
      throw new GoogleConnectionError("google_connection_owner_conflict", 409);
    }
    matches.push(row);
  }
  const unique = new Map(matches.map((row) => [row.connection_id, row]));
  if (unique.size > 1) throw new GoogleConnectionError("google_connection_ambiguous", 409);
  return [...unique.values()][0] || null;
}

export async function googleProxy(config, kind, { connection, path, query, body, raw = false }, { fetchImpl = fetch } = {}) {
  const profile = googleProfile(config, kind, connection?.subject);
  if (!profile || profile.integrationId !== connection?.integrationId || typeof connection.id !== "string") {
    throw new GoogleConnectionError("google_connection_binding_invalid", 403);
  }
  const allowedPrefix = kind === "gmail" ? "/gmail/v1/" : kind === "gdrive" ? "/drive/v3/" : "/calendar/v3/";
  const identityRead = path === "/oauth2/v2/userinfo";
  if (typeof path !== "string" || (!path.startsWith(allowedPrefix) && !identityRead) || path.includes("?") || path.includes("#")
      || (body && (kind !== "gcalendar" || path !== "/calendar/v3/freeBusy"))) {
    throw new GoogleConnectionError("google_endpoint_forbidden", 403);
  }
  const url = new URL(`${config.nango.serverUrl}/proxy${path}`);
  if (url.pathname !== `/proxy${path}`) throw new GoogleConnectionError("google_endpoint_forbidden", 403);
  for (const [name, value] of Object.entries(query || {})) {
    if (value !== undefined && value !== null && value !== "") url.searchParams.set(name, String(value));
  }
  let response;
  try {
    response = await fetchImpl(url, { method: body ? "POST" : "GET", redirect: "error",
      headers: { ...headers(config), "Provider-Config-Key": connection.integrationId, "Connection-Id": connection.id,
        "Base-Url-Override": "https://www.googleapis.com", Retries: "0" },
      ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(profile.timeoutMs || 20000) });
  } catch { throw new GoogleConnectionError("google_upstream_unavailable"); }
  const limit = 12 * 1024 * 1024;
  if (Number(response.headers?.get?.("content-length")) > limit) {
    await response.body?.cancel?.().catch(() => {});
    throw new GoogleConnectionError("google_response_too_large");
  }
  let text = "";
  if (response.body?.getReader) {
    const reader = response.body.getReader(); let bytes = 0; const chunks = [];
    try {
      for (;;) {
        const result = await reader.read(); if (result.done) break;
        bytes += result.value.byteLength;
        if (bytes > limit) { await reader.cancel(); throw new GoogleConnectionError("google_response_too_large"); }
        chunks.push(Buffer.from(result.value));
      }
      text = Buffer.concat(chunks).toString("utf8");
    } finally { reader.releaseLock(); }
  } else if (typeof response.text === "function") text = await response.text();
  else text = JSON.stringify(await response.json()); // injected test transports
  if (raw) return { ok: response.ok, status: response.status, text };
  let data;
  try { data = text ? JSON.parse(text) : {}; }
  catch { throw new GoogleConnectionError("google_response_invalid"); }
  return { ok: response.ok, status: response.status, data };
}

async function probe(config, kind, connection, fetchImpl, recordedAuthFailure) {
  const path = kind === "gmail" ? "/gmail/v1/users/me/profile" : kind === "gdrive" ? "/drive/v3/about" : "/oauth2/v2/userinfo";
  const fields = kind === "gmail" ? "emailAddress" : kind === "gdrive" ? "user(emailAddress)" : "email,verified_email";
  const result = await googleProxy(config, kind, { connection, path, query: { fields } }, { fetchImpl });
  if (result.ok) return { status: "ready", accountEmail: kind === "gmail" ? result.data.emailAddress
    : kind === "gdrive" ? result.data.user?.emailAddress : result.data.email };
  const reasons = (Array.isArray(result.data?.error?.errors) ? result.data.error.errors : []).map((error) => error.reason);
  const detailedReasons = Array.isArray(result.data?.error?.details) ? result.data.error.details.map((error) => error.reason) : [];
  const authCodes = ["invalid_credentials", "invalid_grant", "token_refresh_failed", "failed_to_refresh_token", "refresh_token_expired"];
  const reconnect = result.status === 401
    || (result.status === 424 && (recordedAuthFailure || authCodes.includes(result.data?.error?.code)))
    || (result.status === 403 && [...reasons, ...detailedReasons].some((reason) => ["insufficientPermissions", "authError", "ACCESS_TOKEN_SCOPE_INSUFFICIENT"].includes(reason)));
  return { status: reconnect ? "reconnect_required" : "unavailable", accountEmail: null };
}

async function centralGrantStatus(config, kind, profile, subject, connectionId, fetchImpl) {
  // Nango refreshes expired access tokens here. Only the grant's scope metadata
  // is inspected; credentials never leave the gateway or enter diagnostics.
  const url = new URL(`${config.nango.serverUrl}/connections/${encodeURIComponent(connectionId)}`);
  url.searchParams.set("provider_config_key", profile.integrationId);
  let response, data;
  try {
    response = await fetchImpl(url, { headers: headers(config), redirect: "error", signal: AbortSignal.timeout(20000) });
    data = await response.json();
  } catch { return "unavailable"; }
  if (!response.ok) return response.status === 424 && data?.error?.code === "invalid_credentials" ? "reconnect_required" : "unavailable";
  const match = selectGoogleConnection([data], { subject, orgId: config.googleConnect.orgId,
    integrationId: profile.integrationId, provider: profile.provider });
  if (match?.connection_id !== connectionId) throw new GoogleConnectionError("google_connection_owner_conflict", 409);
  const raw = data.credentials?.raw?.scope ?? data.credentials?.scope ?? data.credentials?.scopes;
  if (data.credentials?.type !== "OAUTH2" || (typeof raw !== "string" && !Array.isArray(raw))) return "unavailable";
  const scopes = new Set((Array.isArray(raw) ? raw : raw.split(/[\s,]+/)).filter(Boolean)
    .map((scope) => scope === "email" ? SCOPE_PREFIX + "userinfo.email" : scope));
  if ([...scopes].some((scope) => !READ_SCOPES.has(scope))) return "unavailable";
  return SCOPES[kind].every((scope) => scopes.has(SCOPE_PREFIX + scope)) ? "ready" : "reconnect_required";
}

export async function getGoogleConnectionState(config, kind, subject, { fetchImpl = fetch, live = true } = {}) {
  const profile = googleProfile(config, kind, subject);
  const empty = { connectionId: null, existingConnectionId: null, accountEmail: null };
  if (!profile) return { ...empty, status: "pilot_pending", canConnect: false, testingMode: config.googleConnect.testingMode === true };
  const row = selectGoogleConnection(await googleConnectionRows(config, { fetchImpl }), {
    subject, orgId: config.googleConnect.orgId, integrationId: profile.integrationId, provider: profile.provider, allowLegacy: !profile.central });
  const common = { ...empty, integrationId: profile.integrationId, testingMode: profile.testingMode, canConnect: true };
  if (!row) return { ...common, status: profile.central ? "connection_required" : "pilot_pending", canConnect: profile.central };
  const connection = { id: row.connection_id, integrationId: profile.integrationId, subject };
  let checked = { status: "ready", accountEmail: null };
  if (profile.central) checked.status = await centralGrantStatus(config, kind, profile, subject, row.connection_id, fetchImpl);
  if (checked.status === "ready" && (live || row.errors?.some((error) => error.type === "auth"))) {
    try { checked = await probe(config, kind, connection, fetchImpl, row.errors?.some((error) => error.type === "auth")); }
    catch { checked = { status: "unavailable", accountEmail: null }; }
  }
  return { ...common, ...checked, existingConnectionId: row.connection_id,
    connectionId: checked.status === "ready" ? row.connection_id : null,
    canConnect: checked.status !== "unavailable" };
}

export async function resolveGoogleConnection(config, kind, subject, options = {}) {
  const state = await getGoogleConnectionState(config, kind, subject, { ...options, live: false });
  if (state.status === "pilot_pending") throw new GoogleConnectionError("google_pilot_pending", 409);
  return state.connectionId ? { id: state.connectionId, integrationId: state.integrationId, subject } : null;
}

export async function createGoogleConnectSession(config, kind, { subject, email = "", displayName = "", connectionId = null }, { fetchImpl = fetch } = {}) {
  const profile = googleProfile(config, kind, subject);
  if (!profile || (!profile.central && !connectionId)) throw new GoogleConnectionError("google_pilot_pending", 409);
  if (connectionId) {
    const row = selectGoogleConnection(await googleConnectionRows(config, { fetchImpl }), {
      subject, orgId: config.googleConnect.orgId, integrationId: profile.integrationId, provider: profile.provider, allowLegacy: !profile.central });
    if (row?.connection_id !== connectionId) throw new GoogleConnectionError("google_reconnect_owner_mismatch", 409);
  }
  const response = await nangoJson(config, `/connect/sessions${connectionId ? "/reconnect" : ""}`, {
    fetchImpl, method: "POST", body: connectionId
      ? { connection_id: connectionId, integration_id: profile.integrationId }
      : { tags: { end_user_id: subject, organization_id: config.googleConnect.orgId,
          ...(email ? { end_user_email: String(email).slice(0, 254) } : {}),
          ...(displayName ? { end_user_display_name: String(displayName).slice(0, 150) } : {}) },
        allowed_integrations: [profile.integrationId] } });
  const data = response.data;
  let url;
  try { url = new URL(data?.connect_link); } catch { throw new GoogleConnectionError("google_connect_link_invalid"); }
  if (url.origin !== (config.googleConnect.connectOrigin || "https://connect.nango.dev") || url.username || url.password) {
    throw new GoogleConnectionError("google_connect_link_invalid");
  }
  const expiry = Date.parse(data.expires_at);
  if (!Number.isFinite(expiry) || expiry <= Date.now() || expiry > Date.now() + 35 * 60000) throw new GoogleConnectionError("google_connect_expiry_invalid");
  return { connectLink: url.href, expiresAt: expiry, integrationId: profile.integrationId };
}

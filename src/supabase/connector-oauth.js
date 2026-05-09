import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { writeSupabaseConnectorCredential } from "./upstream-mcp-client.js";

export class SupabaseConnectorOAuth {
  constructor(config, { fetchImpl = fetch } = {}) {
    this.config = config;
    this.fetchImpl = fetchImpl;
  }

  canHandle(request) {
    const path = new URL(request.url, this.config.publicBaseUrl).pathname;
    return path === "/connectors/supabase/oauth/start"
      || path === "/connectors/supabase/oauth/callback";
  }

  async handle(request, response) {
    const url = new URL(request.url, this.config.publicBaseUrl);
    if (request.method === "GET" && url.pathname === "/connectors/supabase/oauth/start") {
      return this.start(response);
    }
    if (request.method === "GET" && url.pathname === "/connectors/supabase/oauth/callback") {
      return this.callback(url, response);
    }
    return json(response, 405, { error: "method not allowed" });
  }

  start(response) {
    const readiness = this.readiness();
    if (!readiness.ok) {
      return json(response, 400, {
        error: "supabase oauth connector is not configured",
        missing: readiness.missing,
        callback_url: this.config.supabase.oauth.redirectUri
      });
    }
    const codeVerifier = randomBytes(32).toString("base64url");
    const state = signState({
      nonce: randomBytes(16).toString("base64url"),
      connector_id: this.config.supabase.connectorId,
      code_verifier: codeVerifier,
      issued_at: Date.now()
    }, this.stateSecret());
    const authorize = new URL(this.config.supabase.oauth.authorizationUrl);
    authorize.searchParams.set("response_type", "code");
    authorize.searchParams.set("client_id", this.config.supabase.oauth.clientId);
    authorize.searchParams.set("redirect_uri", this.config.supabase.oauth.redirectUri);
    authorize.searchParams.set("code_challenge", pkceChallenge(codeVerifier));
    authorize.searchParams.set("code_challenge_method", "S256");
    if (this.config.supabase.oauth.scope) {
      authorize.searchParams.set("scope", this.config.supabase.oauth.scope);
    }
    if (this.config.supabase.oauth.resource) {
      authorize.searchParams.set("resource", this.config.supabase.oauth.resource);
    }
    authorize.searchParams.set("state", state);
    response.writeHead(302, { location: authorize.toString(), "cache-control": "no-store" });
    response.end();
  }

  async callback(url, response) {
    const error = url.searchParams.get("error");
    if (error) {
      return html(response, 400, page("Supabase OAuth Error", `<p>${escapeHtml(error)}</p>`));
    }
    const code = url.searchParams.get("code") || "";
    const state = url.searchParams.get("state") || "";
    if (!code || !state) {
      return html(response, 400, page("Supabase OAuth Error", "<p>Missing code or state.</p>"));
    }
    const stateCheck = verifyState(state, this.stateSecret());
    if (!stateCheck.ok || stateCheck.payload.connector_id !== this.config.supabase.connectorId) {
      return html(response, 400, page("Supabase OAuth Error", "<p>Invalid connector state.</p>"));
    }
    if (!this.config.supabase.oauth.tokenUrl) {
      return html(response, 400, page("Supabase OAuth Error", "<p>SUPABASE_OAUTH_TOKEN_URL is required to exchange the authorization code.</p>"));
    }

    const form = new URLSearchParams();
    form.set("grant_type", "authorization_code");
    form.set("code", code);
    form.set("redirect_uri", this.config.supabase.oauth.redirectUri);
    if (stateCheck.payload.code_verifier) {
      form.set("code_verifier", stateCheck.payload.code_verifier);
    }
    if (this.config.supabase.oauth.resource) {
      form.set("resource", this.config.supabase.oauth.resource);
    }
    const tokenAuth = tokenEndpointAuth(this.config, form);

    const tokenResponse = await this.fetchImpl(this.config.supabase.oauth.tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", ...tokenAuth.headers },
      body: form
    });
    const body = await tokenResponse.json();
    if (!tokenResponse.ok) {
      return html(response, 502, page("Supabase OAuth Error", `<p>${escapeHtml(body.error_description || body.error || `Token endpoint returned ${tokenResponse.status}`)}</p>`));
    }
    const credential = await writeSupabaseConnectorCredential(this.config, body);
    return html(response, 200, page("Supabase Connector Installed", `
      <p>Connector <strong>${escapeHtml(this.config.supabase.connectorId)}</strong> is installed.</p>
      <p>Project ref: <code>${escapeHtml(this.config.supabase.projectRef || "not configured")}</code></p>
      <p>Read-only: <code>${String(Boolean(this.config.supabase.readOnly))}</code></p>
      <p>Features: <code>${escapeHtml(this.config.supabase.features.join(","))}</code></p>
      <p>Token type: <code>${escapeHtml(credential.token_type)}</code></p>
    `));
  }

  readiness() {
    const missing = [];
    if (!this.config.supabase.oauth.authorizationUrl) missing.push("SUPABASE_OAUTH_AUTHORIZATION_URL");
    if (!this.config.supabase.oauth.tokenUrl) missing.push("SUPABASE_OAUTH_TOKEN_URL");
    if (!this.config.supabase.oauth.clientId) missing.push("SUPABASE_OAUTH_CLIENT_ID");
    if (!this.config.supabase.oauth.redirectUri) missing.push("SUPABASE_OAUTH_REDIRECT_URI");
    if (!this.stateSecret()) missing.push("SUPABASE_OAUTH_STATE_SECRET or MCP_SESSION_SECRET");
    return { ok: missing.length === 0, missing };
  }

  stateSecret() {
    return this.config.supabase.oauth.stateSecret || this.config.sessionSecret || "";
  }
}

function signState(payload, secret) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function pkceChallenge(verifier) {
  return createHash("sha256").update(verifier).digest("base64url");
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

function verifyState(value, secret) {
  const [encoded, signature] = String(value || "").split(".");
  if (!encoded || !signature || !secret) {
    return { ok: false, payload: {} };
  }
  const expected = createHmac("sha256", secret).update(encoded).digest("base64url");
  const ok = safeEqual(signature, expected);
  if (!ok) {
    return { ok: false, payload: {} };
  }
  try {
    return { ok: true, payload: JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) };
  } catch {
    return { ok: false, payload: {} };
  }
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function page(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title><style>body{font-family:ui-sans-serif,system-ui;margin:4rem;max-width:44rem;line-height:1.5}code{background:#f4f4f4;padding:.1rem .25rem}</style></head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`;
}

function html(response, status, body) {
  response.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  response.end(body);
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;" }[char]));
}

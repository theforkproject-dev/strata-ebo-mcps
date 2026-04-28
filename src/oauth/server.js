import { OAuthFileStore, OAuthMemoryStore, randomToken } from "./store.js";
import { safeEqual, sha256Hex, verifyPkce } from "./pkce.js";

const SCOPES = "mcp:read mcp:write";

export class OAuthServer {
  constructor(config) {
    this.config = config;
    this.store = config.oauth.storePath
      ? new OAuthFileStore({ filePath: config.oauth.storePath })
      : new OAuthMemoryStore();
  }

  canHandle(request) {
    const path = new URL(request.url, this.config.publicBaseUrl).pathname;
    return path === "/.well-known/oauth-protected-resource"
      || path === "/.well-known/oauth-authorization-server"
      || path === "/oauth/register"
      || path === "/oauth/authorize"
      || path === "/oauth/token"
      || path === "/oauth/revoke";
  }

  async handle(request, response) {
    const path = new URL(request.url, this.config.publicBaseUrl).pathname;
    try {
      if (request.method === "GET" && path === "/.well-known/oauth-protected-resource") {
        return json(response, 200, {
          resource: `${this.config.publicBaseUrl}/mcp`,
          authorization_servers: [this.config.oauth.issuer],
          scopes_supported: SCOPES.split(" ")
        }, { "cache-control": "max-age=3600" });
      }

      if (request.method === "GET" && path === "/.well-known/oauth-authorization-server") {
        return json(response, 200, {
          issuer: this.config.oauth.issuer,
          authorization_endpoint: `${this.config.oauth.issuer}/oauth/authorize`,
          token_endpoint: `${this.config.oauth.issuer}/oauth/token`,
          registration_endpoint: `${this.config.oauth.issuer}/oauth/register`,
          revocation_endpoint: `${this.config.oauth.issuer}/oauth/revoke`,
          scopes_supported: SCOPES.split(" "),
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          code_challenge_methods_supported: ["S256"],
          token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
          revocation_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"]
        }, { "cache-control": "max-age=3600" });
      }

      if (request.method === "POST" && path === "/oauth/register") {
        return this.handleRegister(request, response);
      }

      if (request.method === "GET" && path === "/oauth/authorize") {
        return this.handleAuthorizeGet(request, response);
      }

      if (request.method === "POST" && path === "/oauth/authorize") {
        return this.handleAuthorizePost(request, response);
      }

      if (request.method === "POST" && path === "/oauth/token") {
        return this.handleToken(request, response);
      }

      if (request.method === "POST" && path === "/oauth/revoke") {
        return this.handleRevoke(request, response);
      }

      return oauthError(response, 405, "invalid_request", "method not allowed");
    } catch (error) {
      return oauthError(response, 500, "server_error", error.message);
    }
  }

  validateAccessToken(token) {
    return this.store.getAccessToken(token);
  }

  async handleRegister(request, response) {
    const body = await readJson(request);
    const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
    if (redirectUris.length === 0) {
      return oauthError(response, 400, "invalid_request", "redirect_uris is required");
    }
    if (!redirectUris.every(isValidRedirectUri)) {
      return oauthError(response, 400, "invalid_request", "redirect_uris must be HTTPS URLs, localhost, or 127.0.0.1");
    }

    const authMethod = body.token_endpoint_auth_method || "none";
    if (!["none", "client_secret_post", "client_secret_basic"].includes(authMethod)) {
      return oauthError(response, 400, "invalid_request", "unsupported token_endpoint_auth_method");
    }

    const client = {
      client_id: randomToken("strata_cl"),
      client_secret: authMethod === "none" ? "" : randomToken("strata_cs"),
      client_name: body.client_name || "MCP Client",
      redirect_uris: redirectUris,
      grant_types: body.grant_types || ["authorization_code", "refresh_token"],
      response_types: body.response_types || ["code"],
      token_endpoint_auth_method: authMethod,
      client_id_issued_at: Math.floor(Date.now() / 1000)
    };
    this.store.saveClient(client);

    return json(response, 201, {
      client_id: client.client_id,
      ...(client.client_secret ? { client_secret: client.client_secret } : {}),
      client_name: client.client_name,
      redirect_uris: client.redirect_uris,
      grant_types: client.grant_types,
      response_types: client.response_types,
      token_endpoint_auth_method: client.token_endpoint_auth_method,
      client_id_issued_at: client.client_id_issued_at
    }, { "cache-control": "no-store" });
  }

  handleAuthorizeGet(request, response, message = "") {
    const url = new URL(request.url, this.config.publicBaseUrl);
    const params = Object.fromEntries(url.searchParams.entries());
    const validation = this.validateAuthorizeParams(params);
    if (!validation.ok) {
      return html(response, 400, errorPage(validation.error));
    }
    return html(response, 200, consentPage({ params, client: validation.client, message }));
  }

  async handleAuthorizePost(request, response) {
    const form = await readForm(request);
    const params = Object.fromEntries(form.entries());
    const validation = this.validateAuthorizeParams(params);
    if (!validation.ok) {
      return html(response, 400, errorPage(validation.error));
    }
    if (!this.verifyConsentPassword(params.passphrase || "")) {
      return html(response, 401, consentPage({ params, client: validation.client, message: "Invalid passphrase." }));
    }

    const code = randomToken("strata_code");
    this.store.saveCode({
      code,
      client_id: params.client_id,
      redirect_uri: params.redirect_uri,
      code_challenge: params.code_challenge,
      code_challenge_method: params.code_challenge_method,
      scope: params.scope || SCOPES,
      expires_at: Date.now() + this.config.oauth.codeTtlMs,
      used: false
    });

    const redirect = new URL(params.redirect_uri);
    redirect.searchParams.set("code", code);
    if (params.state) {
      redirect.searchParams.set("state", params.state);
    }
    response.writeHead(302, { location: redirect.toString(), "cache-control": "no-store" });
    response.end();
  }

  async handleToken(request, response) {
    const form = await readForm(request);
    const grantType = form.get("grant_type");
    const auth = this.authenticateClient(request, form);
    if (!auth.ok) {
      return oauthError(response, 401, "invalid_client", auth.error);
    }
    if (grantType === "authorization_code") {
      return this.exchangeCode(response, form, auth.client);
    }
    if (grantType === "refresh_token") {
      return this.refreshToken(response, form, auth.client);
    }
    return oauthError(response, 400, "unsupported_grant_type", "supported grants: authorization_code, refresh_token");
  }

  handleRevoke = async (request, response) => {
    const form = await readForm(request);
    const auth = this.authenticateClient(request, form, { allowMissingPublicClient: true });
    if (!auth.ok) {
      return oauthError(response, 401, "invalid_client", auth.error);
    }
    const token = form.get("token");
    if (token) {
      this.store.revoke(token);
    }
    response.writeHead(200, { "cache-control": "no-store" });
    response.end();
  };

  exchangeCode(response, form, client) {
    const code = this.store.consumeCode(form.get("code"));
    if (!code || code.client_id !== client.client_id) {
      return oauthError(response, 400, "invalid_grant", "authorization code is invalid or expired");
    }
    if (code.redirect_uri !== form.get("redirect_uri")) {
      return oauthError(response, 400, "invalid_grant", "redirect_uri mismatch");
    }
    if (!verifyPkce({
      verifier: form.get("code_verifier"),
      challenge: code.code_challenge,
      method: code.code_challenge_method
    })) {
      return oauthError(response, 400, "invalid_grant", "PKCE verification failed");
    }
    return this.issueTokens(response, client, code.scope);
  }

  refreshToken(response, form, client) {
    const prior = this.store.consumeRefreshToken(form.get("refresh_token"));
    if (!prior || prior.client_id !== client.client_id) {
      return oauthError(response, 400, "invalid_grant", "refresh token is invalid or expired");
    }
    return this.issueTokens(response, client, prior.scope);
  }

  issueTokens(response, client, scope) {
    const now = Date.now();
    const accessToken = {
      access_token: randomToken("strata_at"),
      client_id: client.client_id,
      scope,
      expires_at: now + this.config.oauth.accessTokenTtlMs,
      revoked: false
    };
    const refreshToken = {
      refresh_token: randomToken("strata_rt"),
      client_id: client.client_id,
      scope,
      expires_at: now + this.config.oauth.refreshTokenTtlMs,
      revoked: false
    };
    this.store.saveAccessToken(accessToken);
    this.store.saveRefreshToken(refreshToken);
    return json(response, 200, {
      access_token: accessToken.access_token,
      token_type: "Bearer",
      expires_in: Math.floor(this.config.oauth.accessTokenTtlMs / 1000),
      refresh_token: refreshToken.refresh_token,
      scope
    }, { "cache-control": "no-store" });
  }

  validateAuthorizeParams(params) {
    const client = this.store.getClient(params.client_id);
    if (!client) {
      return { ok: false, error: "Unknown OAuth client." };
    }
    if (params.response_type !== "code") {
      return { ok: false, error: "response_type must be code." };
    }
    if (!client.redirect_uris.includes(params.redirect_uri)) {
      return { ok: false, error: "redirect_uri is not registered for this client." };
    }
    if (!params.code_challenge || params.code_challenge_method !== "S256") {
      return { ok: false, error: "PKCE S256 code_challenge is required." };
    }
    return { ok: true, client };
  }

  authenticateClient(request, form, options = {}) {
    const basic = parseBasicAuth(request.headers.authorization || "");
    const clientId = basic?.clientId || form.get("client_id");
    if (!clientId) {
      return { ok: false, error: "client_id is required" };
    }
    const client = this.store.getClient(clientId);
    if (!client) {
      return { ok: false, error: "unknown client" };
    }
    if (client.token_endpoint_auth_method === "none") {
      return { ok: true, client };
    }
    const secret = basic?.clientSecret || form.get("client_secret") || "";
    if (!secret || !safeEqual(secret, client.client_secret)) {
      return { ok: false, error: "client_secret is invalid" };
    }
    return { ok: true, client };
  }

  verifyConsentPassword(passphrase) {
    const { consentPassword, consentPasswordHash } = this.config.oauth;
    if (consentPasswordHash) {
      return safeEqual(sha256Hex(passphrase), consentPasswordHash);
    }
    if (consentPassword) {
      return safeEqual(passphrase, consentPassword);
    }
    return false;
  }
}

function consentPage({ params, client, message }) {
  const hidden = ["response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"]
    .map((name) => `<input type="hidden" name="${name}" value="${escapeHtml(params[name] || "")}">`)
    .join("\n");
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Connect Strata Email MCP</title>
<style>body{font-family:ui-sans-serif,system-ui;margin:4rem;max-width:42rem;line-height:1.5}input{font:inherit;padding:.7rem;width:100%;box-sizing:border-box}button{font:inherit;padding:.7rem 1rem;margin-top:1rem}.error{color:#a40000}</style></head>
<body><h1>Connect Strata Email MCP</h1>
<p><strong>${escapeHtml(client.client_name)}</strong> is requesting access to discover and call Strata verified email tools.</p>
<p>This allows the client to call MCP tools. Consequential sends still pass through the Strata witnessed gateway.</p>
${message ? `<p class="error">${escapeHtml(message)}</p>` : ""}
<form method="post" action="/oauth/authorize">
${hidden}
<label>Operator passphrase<br><input type="password" name="passphrase" autofocus required></label>
<button type="submit">Authorize</button>
</form></body></html>`;
}

function errorPage(message) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>OAuth Error</title></head><body><h1>OAuth Error</h1><p>${escapeHtml(message)}</p></body></html>`;
}

function parseBasicAuth(header) {
  if (!header.startsWith("Basic ")) {
    return null;
  }
  const raw = Buffer.from(header.slice("Basic ".length), "base64").toString("utf8");
  const colon = raw.indexOf(":");
  if (colon === -1) {
    return null;
  }
  return {
    clientId: decodeURIComponent(raw.slice(0, colon)),
    clientSecret: decodeURIComponent(raw.slice(colon + 1))
  };
}

function isValidRedirectUri(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || (url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname));
  } catch {
    return false;
  }
}

async function readJson(request) {
  const raw = await readBody(request);
  return raw ? JSON.parse(raw) : {};
}

async function readForm(request) {
  return new URLSearchParams(await readBody(request));
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function json(response, status, body, headers = {}) {
  response.writeHead(status, { "content-type": "application/json", ...headers });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

function html(response, status, body) {
  response.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  response.end(body);
}

function oauthError(response, status, error, description) {
  return json(response, status, { error, error_description: description }, { "cache-control": "no-store" });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"]/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;"
  }[char]));
}

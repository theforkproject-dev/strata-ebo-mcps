#!/usr/bin/env node
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { resolve, join } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const host = "127.0.0.1";
const port = Number(process.env.PORT || 8900);
const issuer = `http://${host}:${port}`;
const passphrase = "oauth-smoke-passphrase";

const child = spawn(process.execPath, [join(root, "src", "server.js")], {
  cwd: root,
  env: {
    ...process.env,
    HOST: host,
    PORT: String(port),
    EMAIL_PROVIDER: "dry-run",
    EMAIL_FROM: "Verified Agent <verified-agent@example.com>",
    DATA_DIR: join(root, "artifacts", "oauth-smoke"),
    OAUTH_ISSUER: issuer,
    OAUTH_CONSENT_PASSWORD: passphrase,
    MCP_SESSION_SECRET: "oauth-smoke-session-secret-32-bytes-minimum"
  },
  stdio: ["ignore", "pipe", "pipe"]
});

child.stderr.on("data", (chunk) => process.stderr.write(chunk));
child.stdout.on("data", (chunk) => process.stderr.write(chunk));

try {
  await waitForHealth(`${issuer}/health`);

  const metadata = await getJson(`${issuer}/.well-known/oauth-authorization-server`);
  const registration = await postJson(`${issuer}/oauth/register`, {
    client_name: "OAuth Smoke Client",
    redirect_uris: ["http://127.0.0.1/callback"],
    token_endpoint_auth_method: "none"
  });

  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const authorize = new URL(`${issuer}/oauth/authorize`);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("client_id", registration.client_id);
  authorize.searchParams.set("redirect_uri", "http://127.0.0.1/callback");
  authorize.searchParams.set("scope", "mcp:read mcp:write");
  authorize.searchParams.set("state", "smoke-state");
  authorize.searchParams.set("code_challenge", challenge);
  authorize.searchParams.set("code_challenge_method", "S256");

  const authForm = new URLSearchParams(authorize.searchParams);
  authForm.set("passphrase", passphrase);
  const authResponse = await fetch(`${issuer}/oauth/authorize`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: authForm,
    redirect: "manual"
  });
  if (authResponse.status !== 302) {
    throw new Error(`authorize returned ${authResponse.status}: ${await authResponse.text()}`);
  }
  const location = authResponse.headers.get("location");
  const code = new URL(location).searchParams.get("code");

  const token = await postForm(`${issuer}/oauth/token`, {
    grant_type: "authorization_code",
    client_id: registration.client_id,
    code,
    redirect_uri: "http://127.0.0.1/callback",
    code_verifier: verifier
  });

  const mcpResponse = await fetch(`${issuer}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token.access_token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "oauth-smoke", version: "0.1.0" } } })
  });
  const mcpBody = await mcpResponse.json();
  if (!mcpResponse.ok || mcpBody.error) {
    throw new Error(`authenticated MCP initialize failed: ${JSON.stringify(mcpBody)}`);
  }

  console.log(JSON.stringify({
    ok: true,
    issuer: metadata.issuer,
    client_id_prefix: registration.client_id.split("_").slice(0, 2).join("_"),
    token_type: token.token_type,
    mcp_protocol: mcpBody.result.protocolVersion
  }, null, 2));
} finally {
  child.kill("SIGTERM");
}

async function getJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}: ${await response.text()}`);
  }
  return response.json();
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}: ${await response.text()}`);
  }
  return response.json();
}

async function postForm(url, fields) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields)
  });
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}: ${await response.text()}`);
  }
  return response.json();
}

async function waitForHealth(url) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      // Keep polling.
    }
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${url}`);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

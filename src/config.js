import { existsSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";

export function loadConfig(env = process.env) {
  loadDotEnv(env);

  const sessionSecret = env.MCP_SESSION_SECRET || randomBytes(32).toString("hex");
  const dataDir = env.DATA_DIR || "artifacts/email-mcp";
  const publicBaseUrl = trimSlash(env.PUBLIC_BASE_URL || `http://${env.HOST || "127.0.0.1"}:${env.PORT || "8899"}`);

  return {
    host: env.HOST || "127.0.0.1",
    port: Number(env.PORT || 8899),
    sessionSecret,
    sessionSecretWasGenerated: !env.MCP_SESSION_SECRET,
    bearerToken: env.MCP_BEARER_TOKEN || "",
    allowedOrigins: parseCsv(env.MCP_ALLOWED_ORIGINS || ""),
    dataDir,
    publicBaseUrl,
    certificateBaseUrl: trimSlash(env.CERTIFICATE_BASE_URL || `${publicBaseUrl}/certificates`),
    email: {
      provider: env.EMAIL_PROVIDER || "resend",
      from: env.EMAIL_FROM || "",
      resendApiKey: env.RESEND_API_KEY || "",
      resendBaseUrl: trimSlash(env.RESEND_BASE_URL || "https://api.resend.com")
    },
    oauth: {
      enabled: Boolean(env.OAUTH_ISSUER),
      issuer: trimSlash(env.OAUTH_ISSUER || publicBaseUrl),
      storePath: env.OAUTH_STORE_PATH || `${dataDir}/oauth-store.json`,
      consentPassword: env.OAUTH_CONSENT_PASSWORD || "",
      consentPasswordHash: env.OAUTH_CONSENT_PASSWORD_SHA256 || "",
      accessTokenTtlMs: Number(env.OAUTH_ACCESS_TOKEN_TTL_SECONDS || 3600) * 1000,
      refreshTokenTtlMs: Number(env.OAUTH_REFRESH_TOKEN_TTL_SECONDS || 30 * 24 * 3600) * 1000,
      codeTtlMs: Number(env.OAUTH_CODE_TTL_SECONDS || 600) * 1000
    },
    witnesses: parseWitnessUrls(env.WITNESS_URLS || "", "w"),
    policyWitnesses: parseWitnessUrls(env.POLICY_WITNESS_URLS || "", "p")
  };
}

export function parseWitnessUrls(value, prefix = "w") {
  return parseCsv(value).map((item, index) => {
    const eq = item.indexOf("=");
    if (eq === -1) {
      return { id: `${prefix}${index + 1}`, url: item };
    }
    return { id: item.slice(0, eq).trim(), url: item.slice(eq + 1).trim() };
  }).filter((item) => item.id && item.url);
}

function parseCsv(value) {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function trimSlash(value) {
  return String(value).replace(/\/$/, "");
}

function loadDotEnv(env) {
  if (!existsSync(".env")) {
    return;
  }

  const raw = readFileSync(".env", "utf8");
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq === -1) {
      continue;
    }
    const key = trimmed.slice(0, eq).trim();
    if (env[key]) {
      continue;
    }
    env[key] = unquote(trimmed.slice(eq + 1).trim());
  }
}

function unquote(value) {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}

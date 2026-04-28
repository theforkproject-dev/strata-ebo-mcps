import { createHmac, randomBytes } from "node:crypto";

export class SessionManager {
  constructor({ secret, ttlMs = 60 * 60 * 1000 }) {
    if (!secret || Buffer.byteLength(secret) < 32) {
      throw new Error("MCP_SESSION_SECRET must be at least 32 bytes");
    }
    this.secret = secret;
    this.ttlMs = ttlMs;
  }

  createSession({ agentId = "mcp-client" } = {}) {
    const now = Date.now();
    const payload = {
      sid: randomBytes(16).toString("hex"),
      aid: agentId,
      iat: now,
      exp: now + this.ttlMs
    };
    return signPayload(payload, this.secret);
  }

  validateSession(token) {
    if (!token) {
      return null;
    }
    const parts = token.split(".");
    if (parts.length !== 2) {
      return null;
    }
    const [body, signature] = parts;
    if (signature !== hmac(body, this.secret)) {
      return null;
    }
    let payload;
    try {
      payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    } catch {
      return null;
    }
    if (!payload.exp || payload.exp < Date.now()) {
      return null;
    }
    return payload;
  }
}

function signPayload(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${body}.${hmac(body, secret)}`;
}

function hmac(value, secret) {
  return createHmac("sha256", secret).update(value).digest("base64url");
}

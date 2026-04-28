import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export class OAuthMemoryStore {
  constructor(clock = () => new Date()) {
    this.clock = clock;
    this.clients = new Map();
    this.codes = new Map();
    this.accessTokens = new Map();
    this.refreshTokens = new Map();
  }

  saveClient(client) {
    this.clients.set(client.client_id, client);
    return client;
  }

  getClient(clientId) {
    return this.clients.get(clientId) || null;
  }

  saveCode(code) {
    this.codes.set(code.code, code);
    return code;
  }

  consumeCode(codeValue) {
    const code = this.codes.get(codeValue);
    if (!code || code.used || code.expires_at < this.clock().getTime()) {
      return null;
    }
    code.used = true;
    return code;
  }

  saveAccessToken(token) {
    this.accessTokens.set(token.access_token, token);
    return token;
  }

  getAccessToken(value) {
    const token = this.accessTokens.get(value);
    if (!token || token.revoked || token.expires_at < this.clock().getTime()) {
      return null;
    }
    return token;
  }

  saveRefreshToken(token) {
    this.refreshTokens.set(token.refresh_token, token);
    return token;
  }

  consumeRefreshToken(value) {
    const token = this.refreshTokens.get(value);
    if (!token || token.revoked || token.expires_at < this.clock().getTime()) {
      return null;
    }
    token.revoked = true;
    return token;
  }

  revoke(value) {
    const access = this.accessTokens.get(value);
    if (access) {
      access.revoked = true;
    }
    const refresh = this.refreshTokens.get(value);
    if (refresh) {
      refresh.revoked = true;
    }
  }
}

export class OAuthFileStore extends OAuthMemoryStore {
  constructor({ filePath, clock = () => new Date() }) {
    super(clock);
    if (!filePath) {
      throw new Error("OAuthFileStore requires filePath");
    }
    this.filePath = filePath;
    this.load();
  }

  saveClient(client) {
    const result = super.saveClient(client);
    this.persist();
    return result;
  }

  saveCode(code) {
    const result = super.saveCode(code);
    this.persist();
    return result;
  }

  consumeCode(codeValue) {
    const result = super.consumeCode(codeValue);
    if (result) {
      this.persist();
    }
    return result;
  }

  saveAccessToken(token) {
    const result = super.saveAccessToken(token);
    this.persist();
    return result;
  }

  saveRefreshToken(token) {
    const result = super.saveRefreshToken(token);
    this.persist();
    return result;
  }

  consumeRefreshToken(value) {
    const result = super.consumeRefreshToken(value);
    if (result) {
      this.persist();
    }
    return result;
  }

  revoke(value) {
    super.revoke(value);
    this.persist();
  }

  load() {
    if (!existsSync(this.filePath)) {
      return;
    }
    const raw = readFileSync(this.filePath, "utf8");
    if (!raw.trim()) {
      return;
    }
    const state = JSON.parse(raw);
    this.clients = mapFromEntries(state.clients, "client_id");
    this.codes = mapFromEntries(state.codes, "code");
    this.accessTokens = mapFromEntries(state.access_tokens, "access_token");
    this.refreshTokens = mapFromEntries(state.refresh_tokens, "refresh_token");
  }

  persist() {
    mkdirSync(dirname(this.filePath), { recursive: true });
    const state = {
      version: "strata.oauth.store.v1",
      saved_at: new Date().toISOString(),
      clients: [...this.clients.values()],
      codes: [...this.codes.values()],
      access_tokens: [...this.accessTokens.values()],
      refresh_tokens: [...this.refreshTokens.values()]
    };
    const tmpPath = `${this.filePath}.${process.pid}.tmp`;
    writeFileSync(tmpPath, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    renameSync(tmpPath, this.filePath);
  }
}

export function randomToken(prefix) {
  return `${prefix}_${randomBytes(32).toString("base64url")}`;
}

function mapFromEntries(entries, key) {
  const map = new Map();
  for (const entry of entries || []) {
    if (entry?.[key]) {
      map.set(entry[key], entry);
    }
  }
  return map;
}

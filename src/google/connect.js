import { createHash, timingSafeEqual, randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from "node:fs";
import { join } from "node:path";
import { GoogleConnectionError, googleSubject, getGoogleConnectionState, createGoogleConnectSession } from "./client.js";

// Cover the maximum accepted 35-minute link lifetime plus the bounded reconnect
// ownership inventory (at most ten 20-second requests) and session-create call.
const UNKNOWN_ATTEMPT_HOLD_MS = 40 * 60000;

export function authorizeGoogleControl(config, request) {
  const token = /^Bearer ([^\s]{1,1024})$/.exec(String(request.headers?.authorization || ""))?.[1];
  const expected = config.oauth?.consentPasswordHash
    || (config.oauth?.consentPassword ? createHash("sha256").update(config.oauth.consentPassword).digest("hex") : "");
  if (!expected || !/^[a-f0-9]{64}$/i.test(expected)) throw new GoogleConnectionError("google_control_not_configured");
  const actual = createHash("sha256").update(token || "").digest();
  if (!token || !timingSafeEqual(actual, Buffer.from(expected, "hex"))) throw new GoogleConnectionError("not_authorized", 401);
}

/* Short-lived Connect links are private bearer capabilities. Persist before
 * returning them so a reload/restart reuses the same attempt. An ambiguous
 * create is held until its bounded lifetime expires rather than replayed. */
export class GoogleSessionStore {
  constructor(dataDir) { this.path = join(dataDir, "google-connect-sessions.json"); this.dataDir = dataDir; }
  read() {
    if (!existsSync(this.path)) return {};
    let rows;
    try { rows = JSON.parse(readFileSync(this.path, "utf8")); }
    catch { throw new GoogleConnectionError("google_attempt_store_unavailable"); }
    if (!rows || typeof rows !== "object" || Array.isArray(rows)) throw new GoogleConnectionError("google_attempt_store_unavailable");
    return Object.fromEntries(Object.entries(rows).filter(([, row]) => Number(row?.expiresAt) > Date.now()));
  }
  get(key) { return this.read()[key] || null; }
  put(key, value) {
    const rows = this.read();
    if (!rows[key] && Object.keys(rows).length >= 1000) throw new GoogleConnectionError("google_attempt_capacity");
    rows[key] = value;
    mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    const temp = `${this.path}.${randomUUID()}.tmp`;
    writeFileSync(temp, JSON.stringify(rows), { mode: 0o600 }); renameSync(temp, this.path);
  }
}

export class GoogleConnect {
  constructor(config, kind, { fetchImpl = fetch, store = new GoogleSessionStore(config.dataDir) } = {}) {
    this.config = config; this.kind = kind; this.fetchImpl = fetchImpl; this.store = store; this.pending = new Map();
    this.base = `/connectors/nango/${kind}`;
  }
  canHandle(request) {
    const path = new URL(request.url, this.config.publicBaseUrl).pathname;
    return ["/status", "/session", "/start"].some((suffix) => path === this.base + suffix);
  }
  async handle(request, response) {
    try {
      authorizeGoogleControl(this.config, request);
      const url = new URL(request.url, this.config.publicBaseUrl);
      if (request.method === "GET" && url.pathname === this.base + "/status") {
        const subject = googleSubject(this.config, url.searchParams.get("end_user_id"));
        const state = await getGoogleConnectionState(this.config, this.kind, subject, { fetchImpl: this.fetchImpl });
        return json(response, 200, { status: state.status, can_connect: state.canConnect,
          account_email: state.accountEmail || null, testing_mode: state.testingMode });
      }
      if (request.method === "POST" && url.pathname === this.base + "/session") {
        let raw = "";
        for await (const chunk of request) {
          raw += chunk.toString("utf8");
          if (Buffer.byteLength(raw) > 4096) throw new GoogleConnectionError("request_too_large", 413);
        }
        let input;
        try { input = JSON.parse(raw); } catch { throw new GoogleConnectionError("invalid_request", 400); }
        const subject = googleSubject(this.config, input?.subject);
        if (!this.pending.has(subject)) {
          const work = this.session(subject, input).finally(() => this.pending.delete(subject));
          this.pending.set(subject, work);
        }
        const result = await this.pending.get(subject);
        return json(response, 200, { connect_url: result.connectLink, expires_at: new Date(result.expiresAt).toISOString() });
      }
      return json(response, 405, { error: "Use the authenticated Agent Anything connection flow." });
    } catch (error) {
      return json(response, error instanceof GoogleConnectionError ? error.status : 503,
        { error: error instanceof GoogleConnectionError ? error.code : "google_connection_unavailable" });
    }
  }
  async session(subject, input) {
    const state = await getGoogleConnectionState(this.config, this.kind, subject, { fetchImpl: this.fetchImpl });
    if (!state.canConnect) throw new GoogleConnectionError(state.status === "pilot_pending" ? "google_pilot_pending" : "google_connection_unavailable", 409);
    const key = createHash("sha256").update(`${this.kind}\n${state.integrationId}\n${subject}`).digest("hex");
    const cached = this.store.get(key);
    if (cached && cached.connectionId === state.existingConnectionId) {
      if (cached.connectLink) return cached;
      throw new GoogleConnectionError("google_connection_attempt_pending", 409);
    }
    const pending = { expiresAt: Date.now() + UNKNOWN_ATTEMPT_HOLD_MS, connectionId: state.existingConnectionId };
    this.store.put(key, pending);
    const result = await createGoogleConnectSession(this.config, this.kind,
      { subject, email: typeof input.email === "string" ? input.email : "",
        displayName: typeof input.display_name === "string" ? input.display_name : "", connectionId: state.existingConnectionId },
      { fetchImpl: this.fetchImpl });
    const saved = { ...pending, ...result };
    this.store.put(key, saved); return saved;
  }
}

function json(response, status, body) {
  response.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  response.end(JSON.stringify(body));
}

import assert from "node:assert/strict";
import test from "node:test";
import { Readable } from "node:stream";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GoogleConnect, GoogleSessionStore } from "../src/google/connect.js";

const subject = "aa:acme:usr_alice";
const config = (dataDir) => ({ dataDir, publicBaseUrl: "https://gateway.test", oauth: { consentPassword: "test-control-password" },
  nango: { serverUrl: "https://nango.test", secretKey: "never-expose-nango-key" },
  googleConnect: { orgId: "acme", pilotSubjects: [], testingMode: true }, gmail: { providerConfigKey: "google-mail", timeoutMs: 1000 } });
async function call(handler, { method = "POST", path = "/session", body = { subject }, authorized = true } = {}) {
  const req = Readable.from(method === "POST" ? [JSON.stringify(body)] : []);
  req.url = `/connectors/nango/gmail${path}`; req.method = method;
  req.headers = authorized ? { authorization: "Bearer test-control-password" } : {};
  const out = {}; const res = { writeHead(status, headers) { out.status = status; out.headers = headers; }, end(value) { out.body = JSON.parse(value); } };
  await handler.handle(req, res); return out;
}
test("public start/status and cross-tenant subjects cannot create or inspect a connection", async () => {
  const dir = mkdtempSync(join(tmpdir(), "aa-google-control-"));
  try {
    const handler = new GoogleConnect(config(dir), "gmail", { fetchImpl: () => { throw Error("Must not reach Nango"); } });
    assert.equal((await call(handler, { authorized: false })).status, 401);
    assert.equal((await call(handler, { method: "GET", path: `/status?end_user_id=${subject}`, authorized: false })).status, 401);
    assert.equal((await call(handler, { body: { subject: "aa:other:usr_alice" } })).status, 403);
    assert.equal((await call(handler, { method: "GET", path: "/start" })).status, 405);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("duplicate requests and a gateway restart reuse the same persisted Connect session", async () => {
  const dir = mkdtempSync(join(tmpdir(), "aa-google-control-")); let creates = 0;
  try {
    const fetchImpl = async (url) => {
      if (new URL(url).pathname === "/connections") return Response.json({ connections: [] });
      creates++; await new Promise((resolve) => setTimeout(resolve, 10));
      return Response.json({ data: { connect_link: "https://connect.nango.dev/?session_token=mock", expires_at: new Date(Date.now() + 1800000).toISOString() } });
    };
    const handler = new GoogleConnect(config(dir), "gmail", { fetchImpl });
    const [first, second] = await Promise.all([call(handler), call(handler)]);
    assert.equal(first.status, 200); assert.deepEqual(first.body, second.body); assert.equal(creates, 1);
    const restarted = new GoogleConnect(config(dir), "gmail", { fetchImpl });
    assert.deepEqual((await call(restarted)).body, first.body); assert.equal(creates, 1);
    assert.equal(statSync(new GoogleSessionStore(dir).path).mode & 0o777, 0o600);
    assert.equal(JSON.stringify(first.body).includes("never-expose-nango-key"), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("an ambiguous create survives restart and the maximum possible live-link window", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "aa-google-control-")); let creates = 0;
  const started = Date.now(); let clock = started;
  t.mock.method(Date, "now", () => clock);
  try {
    const fetchImpl = async (url) => {
      if (new URL(url).pathname === "/connections") return Response.json({ connections: [] });
      creates++; throw Error("unknown remote outcome containing fake secret");
    };
    assert.equal((await call(new GoogleConnect(config(dir), "gmail", { fetchImpl }))).status, 503);
    const result = await call(new GoogleConnect(config(dir), "gmail", { fetchImpl }));
    assert.equal(result.status, 409); assert.equal(result.body.error, "google_connection_attempt_pending");
    assert.equal(creates, 1); assert.equal(JSON.stringify(result).includes("fake secret"), false);
    for (const elapsedMinutes of [31, 35, 39]) {
      clock = started + elapsedMinutes * 60000;
      const held = await call(new GoogleConnect(config(dir), "gmail", { fetchImpl }));
      assert.equal(held.status, 409); assert.equal(held.body.error, "google_connection_attempt_pending");
      assert.equal(creates, 1);
    }
    clock = started + 41 * 60000;
    assert.equal((await call(new GoogleConnect(config(dir), "gmail", { fetchImpl }))).status, 503);
    assert.equal(creates, 2, "a new attempt is allowed only after the old link cannot still be live");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

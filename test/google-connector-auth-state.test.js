import assert from "node:assert/strict";
import test from "node:test";
import { getGoogleConnectionState, resolveGoogleConnection, selectGoogleConnection, createGoogleConnectSession, googleProxy } from "../src/google/client.js";

export const subject = "aa:acme:usr_alice";
export function config(kind = "gmail") {
  return { nango: { secretKey: "test-secret", serverUrl: "https://nango.test" },
    googleConnect: { orgId: "acme", pilotSubjects: [], testingMode: true },
    [kind]: { providerConfigKey: kind === "gmail" ? "google-mail" : kind === "gdrive" ? "google-drive" : "google-calendar",
      maxResults: 25, timeoutMs: 1000, assurance: "observed-l1" } };
}
export function row(kind = "gmail", extra = {}) {
  const integration = config(kind)[kind].providerConfigKey;
  return { provider_config_key: integration, provider: integration, connection_id: "alice-connection",
    tags: { end_user_id: subject, organization_id: "acme" }, errors: [], ...extra };
}
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const scope = "gmail.readonly drive.readonly calendar.calendarlist.readonly calendar.events.readonly calendar.events.freebusy userinfo.email".split(" ").map((s) => "https://www.googleapis.com/auth/" + s).join(" ");
const fetcher = (rows, status = 200, error = {}) => async (url) => {
  const path = new URL(url).pathname;
  if (path === "/connections") return json({ connections: rows });
  if (path.startsWith("/connections/")) return json({ ...rows[0], credentials: { type: "OAUTH2", raw: { scope } } });
  return json(status === 200 ? { emailAddress: "alice@example.test", user: { emailAddress: "alice@example.test" }, email: "alice@example.test" } : error, status);
};

for (const kind of ["gmail", "gdrive", "gcalendar"]) {
  test(`${kind}: exact tagged ownership resolves; missing users never receive a demo fallback`, async () => {
    const cfg = config(kind); cfg[kind].fallbackConnectionId = "unsafe-demo";
    assert.deepEqual(await resolveGoogleConnection(cfg, kind, subject, { fetchImpl: fetcher([row(kind)]) }),
      { id: "alice-connection", integrationId: cfg[kind].providerConfigKey, subject });
    assert.equal(await resolveGoogleConnection(cfg, kind, "aa:acme:usr_bob", { fetchImpl: fetcher([row(kind)]) }), null);
    await assert.rejects(resolveGoogleConnection(cfg, kind, "aa:other:usr_alice", { fetchImpl: () => { throw Error("Must not fetch"); } }), /forbidden/);
  });
  test(`${kind}: historical auth error is verified live; expired grants fail closed`, async () => {
    const broken = row(kind, { errors: [{ type: "auth" }] });
    const recovered = await getGoogleConnectionState(config(kind), kind, subject, { fetchImpl: fetcher([broken]) });
    assert.equal(recovered.status, "ready");
    for (const status of [401, 424]) {
      const state = await getGoogleConnectionState(config(kind), kind, subject, { fetchImpl: fetcher([broken], status, { error: { code: "invalid_credentials" } }) });
      assert.equal(state.status, "reconnect_required"); assert.equal(state.connectionId, null);
      assert.equal(state.existingConnectionId, "alice-connection"); assert.equal(state.canConnect, true);
    }
    const unavailable = await getGoogleConnectionState(config(kind), kind, subject, { fetchImpl: fetcher([broken], 503) });
    assert.equal(unavailable.status, "unavailable"); assert.equal(unavailable.canConnect, false);
  });
}

test("legacy owner compatibility does not accept conflicting tags, wrong providers or duplicate identities", () => {
  const options = { subject, orgId: "acme", integrationId: "google-mail", provider: "google-mail", allowLegacy: true };
  const legacy = row("gmail", { tags: undefined, end_user: { id: subject } });
  assert.equal(selectGoogleConnection([legacy], options).connection_id, "alice-connection");
  const backfilled = { ...legacy, tags: { end_user_id: subject } };
  assert.equal(selectGoogleConnection([backfilled], options).connection_id, "alice-connection");
  assert.throws(() => selectGoogleConnection([backfilled], { ...options, allowLegacy: false }), /owner_conflict/);
  assert.throws(() => selectGoogleConnection([legacy], { ...options, allowLegacy: false }), /owner_conflict/);
  for (const bad of [row("gmail", { end_user: { id: "aa:acme:usr_bob" } }),
    row("gmail", { tags: { end_user_id: subject, organization_id: "other" } }), row("gmail", { provider: "google-drive" })]) {
    assert.throws(() => selectGoogleConnection([bad], options), /owner_conflict/);
  }
  assert.throws(() => selectGoogleConnection([row(), row("gmail", { connection_id: "duplicate" })], options), /ambiguous/);
});

test("central pilot selection is explicit and never falls back from a missing central grant", async () => {
  const cfg = config(); cfg.googleConnect.pilotSubjects = [subject];
  cfg.gmail.providerConfigKey = "central-mail"; cfg.gmail.legacyProviderConfigKey = "google-mail";
  const legacyAlice = row("gmail", { tags: undefined, end_user: { id: subject } });
  const legacyBob = row("gmail", { connection_id: "bob-old", tags: undefined, end_user: { id: "aa:acme:usr_bob" } });
  const fetchImpl = fetcher([legacyAlice, legacyBob]);
  assert.equal(await resolveGoogleConnection(cfg, "gmail", subject, { fetchImpl }), null);
  assert.deepEqual(await resolveGoogleConnection(cfg, "gmail", "aa:acme:usr_bob", { fetchImpl }),
    { id: "bob-old", integrationId: "google-mail", subject: "aa:acme:usr_bob" });
  const missing = await getGoogleConnectionState(cfg, "gmail", "aa:acme:usr_new", { fetchImpl });
  assert.equal(missing.status, "pilot_pending"); assert.equal(missing.canConnect, false);
});

test("complete zero-based pagination detects a duplicate on a later page", async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    const page = Number(new URL(url).searchParams.get("page")); calls.push(page);
    return json({ connections: page === 0 ? [row(), ...Array.from({ length: 99 }, (_, i) => row("gmail", {
      connection_id: `other-${i}`, tags: { end_user_id: `aa:acme:usr_other${i}`, organization_id: "acme" } }))]
      : [row("gmail", { connection_id: "late-duplicate" })] });
  };
  await assert.rejects(resolveGoogleConnection(config(), "gmail", subject, { fetchImpl }), /ambiguous/);
  assert.deepEqual(calls, [0, 1]);
});

test("new sessions bind trusted owner tags; reconnect verifies the exact owner before dispatch", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    if (new URL(url).pathname === "/connections") return json({ connections: [row()] });
    calls.push({ url: String(url), body: JSON.parse(options.body) });
    return json({ data: { connect_link: "https://connect.nango.dev/?session_token=mock", expires_at: new Date(Date.now() + 1800000).toISOString() } });
  };
  await createGoogleConnectSession(config(), "gmail", { subject, email: "alice@example.test" }, { fetchImpl });
  assert.deepEqual(calls[0].body.allowed_integrations, ["google-mail"]);
  assert.equal(calls[0].body.tags.end_user_id, subject); assert.equal(calls[0].body.tags.organization_id, "acme");
  await createGoogleConnectSession(config(), "gmail", { subject, connectionId: "alice-connection" }, { fetchImpl });
  assert.equal(calls[1].url, "https://nango.test/connect/sessions/reconnect");
  await assert.rejects(createGoogleConnectSession(config(), "gmail", { subject, connectionId: "somebody-else" }, { fetchImpl }), /owner_mismatch/);
  assert.equal(calls.length, 2);
});

test("read proxy rejects mutation and normalized path escape before network access", async () => {
  const cfg = config("gcalendar"), connection = { id: "c", integrationId: "google-calendar", subject };
  const fetchImpl = () => { throw new Error("Unexpected network access"); };
  await assert.rejects(googleProxy(cfg, "gcalendar", { connection, path: "/calendar/v3/calendars/primary/events", body: {} }, { fetchImpl }), /forbidden/);
  await assert.rejects(googleProxy(cfg, "gcalendar", { connection, path: "/calendar/v3/../../oauth2/v2/userinfo" }, { fetchImpl }), /forbidden/);
});

test("central readiness requires the actual service grants, not only a successful sign-in", async () => {
  for (const grant of ["https://www.googleapis.com/auth/userinfo.email", `${scope} https://mail.google.com/`]) {
    const fetchImpl = async (url) => new URL(url).pathname === "/connections" ? json({ connections: [row()] })
      : json({ ...row(), credentials: { type: "OAUTH2", raw: { scope: grant } } });
    const state = await getGoogleConnectionState(config(), "gmail", subject, { fetchImpl });
    assert.equal(state.connectionId, null);
    assert.equal(state.status, grant.includes("https://mail.google.com/") ? "unavailable" : "reconnect_required");
  }
});

import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { calendarTimeRange, callGcalendarTool, gcalendarToolDefinitions } from "../src/gcalendar/tools.js";
import { GcalendarMcpServer } from "../src/gcalendar-mcp-server.js";

const subject = "aa:acme:usr_alice";
const config = { nango: { serverUrl: "https://nango.test", secretKey: "secret" }, googleConnect: { orgId: "acme", pilotSubjects: [] },
  gcalendar: { providerConfigKey: "calendar-acme", maxResults: 25, timeoutMs: 1000, assurance: "observed-l1" } };
const connection = { provider_config_key: "calendar-acme", provider: "google-calendar", connection_id: "alice-cal",
  tags: { end_user_id: subject, organization_id: "acme" }, errors: [] };
const grant = { ...connection, credentials: { type: "OAUTH2", raw: { scope: ["calendar.calendarlist.readonly", "calendar.events.readonly", "calendar.events.freebusy", "userinfo.email"].map((s) => "https://www.googleapis.com/auth/" + s).join(" ") } } };
test("Calendar exposes only read operations and validates date/window boundaries", () => {
  assert.deepEqual(gcalendarToolDefinitions(config).map((item) => item.name), ["gcalendar_list_calendars", "gcalendar_list_events", "gcalendar_get_event", "gcalendar_free_busy", "gcalendar_gateway_status"]);
  assert.throws(() => calendarTimeRange({ time_min: "2026-02-30T00:00:00Z", time_max: "2026-03-02T00:00:00Z" }, 31));
  assert.throws(() => calendarTimeRange({ time_min: "2026-09-24T00:00:00", time_max: "2026-09-25T00:00:00Z" }, 31));
  assert.throws(() => calendarTimeRange({ time_min: "2026-09-24T00:00:00Z", time_max: "2027-09-24T00:00:00Z" }, 31));
  assert.throws(() => calendarTimeRange({ page_token: "next" }, 366, true), /original_time_window/);
});
test("Calendar pagination and bounded descriptions remain honest; account reference is internal", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    if (new URL(url).pathname === "/connections") return Response.json({ connections: [connection] });
    if (new URL(url).pathname.startsWith("/connections/")) return Response.json(grant);
    calls.push({ url: new URL(url), options });
    return Response.json({ timeZone: "America/New_York", nextPageToken: "page-2", items: [{ id: "event", description: "x".repeat(13000), start: { date: "2026-09-24" }, end: { date: "2026-09-25" } }] });
  };
  const result = await callGcalendarTool({ config, subject, name: "gcalendar_list_events", args: { time_min: "2026-09-24T00:00:00Z", time_max: "2026-09-25T00:00:00Z" } }, { fetchImpl });
  assert.equal(result.ok, true); assert.equal(result.complete, false); assert.equal(result.next_page_token, "page-2");
  assert.equal(result.events[0].all_day, true); assert.equal(result.events[0].description_complete, false);
  assert.equal(calls[0].options.headers["Connection-Id"], "alice-cal");
  assert.equal(calls[0].options.headers["Provider-Config-Key"], "calendar-acme");
  assert.equal(JSON.stringify(result).includes("alice-cal"), false);
});
test("free/busy uses the one allowed read-only POST and reports per-calendar errors", async () => {
  let seen;
  const fetchImpl = async (url, options) => {
    if (new URL(url).pathname === "/connections") return Response.json({ connections: [connection] });
    if (new URL(url).pathname.startsWith("/connections/")) return Response.json(grant);
    seen = { url: new URL(url), options };
    return Response.json({ calendars: { primary: { errors: [{ reason: "notFound" }] } } });
  };
  const result = await callGcalendarTool({ config, subject, name: "gcalendar_free_busy", args: { time_min: "2026-09-24T00:00:00Z", time_max: "2026-09-25T00:00:00Z" } }, { fetchImpl });
  assert.equal(seen.url.pathname, "/proxy/calendar/v3/freeBusy"); assert.equal(seen.options.method, "POST");
  assert.equal(result.complete, false); assert.equal(result.calendars.primary.errors[0].reason, "notFound");
});

test("MCP wrapper advertises the read-only manifest and refuses an unbound caller", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "gcalendar-mcp-"));
  try {
    const server = new GcalendarMcpServer({ ...config, dataDir }, { resolveClientName: async () => "aa:other:usr_alice" });
    const initialized = await server.dispatch({ method: "initialize", params: { protocolVersion: "2025-11-25" } });
    assert.equal(initialized.protocolVersion, "2025-11-25");
    assert.equal((await server.dispatch({ method: "tools/list" })).tools.length, 5);
    assert.equal((await server.dispatch({ method: "tools/call", params: { name: "gcalendar_create_event" } })).isError, true);
    const denied = await server.dispatch({ method: "tools/call", params: { name: "gcalendar_gateway_status" } }, { session: { aid: "fake-client" } });
    assert.equal(denied.isError, true); assert.match(denied.structuredContent.error, /forbidden/);
  } finally { rmSync(dataDir, { recursive: true, force: true }); }
});

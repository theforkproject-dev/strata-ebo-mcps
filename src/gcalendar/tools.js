import { createUsageMeter as createMeter } from "../sharepoint/tools.js";
import { googleConfigured, getGoogleConnectionState, resolveGoogleConnection, googleProxy } from "../google/client.js";

export const createUsageMeter = (dataDir) => createMeter(dataDir, "gcalendar-usage.jsonl");
const KIND = "gcalendar";
const EVENT_FIELDS = "id,status,summary,description,location,start,end,htmlLink,organizer(email,displayName),attendees(email,displayName,responseStatus),recurringEventId,originalStartTime,updated,conferenceData(entryPoints(entryPointType,uri)),attachments(title,fileUrl,mimeType)";
const NAMES = new Set(["gcalendar_list_calendars", "gcalendar_list_events", "gcalendar_get_event", "gcalendar_free_busy", "gcalendar_gateway_status"]);
export const isGcalendarToolName = (name) => NAMES.has(name);

export function gcalendarToolDefinitions(config) {
  const calendar = { type: "string", description: "Calendar id from gcalendar_list_calendars; default primary (your main calendar)." };
  const page = { type: "string", description: "Opaque next_page_token from the previous page. Keep all other filters unchanged." };
  const limit = { type: "integer", minimum: 1, maximum: config.gcalendar.maxResults, description: "Maximum items on this page." };
  const time = { type: "string", description: "RFC3339 timestamp including Z or a UTC offset." };
  return [
    { name: "gcalendar_list_calendars", description: "List calendars available to this user's Google account, including their access role and timezone. Read-only and per-user. Follow next_page_token when complete=false.",
      inputSchema: { type: "object", additionalProperties: false, properties: { max_results: limit, page_token: page } } },
    { name: "gcalendar_list_events", description: "Read/search calendar events in a bounded time window. Defaults to the next seven days on your primary calendar; maximum window 366 days. Recurrences are expanded. Return data is one page, not necessarily the whole schedule: repeat the returned time_min/time_max and other filters with next_page_token until complete=true. Read-only; no event creation or editing.",
      inputSchema: { type: "object", additionalProperties: false, properties: { calendar_id: calendar, time_min: time, time_max: time,
        query: { type: "string", maxLength: 500, description: "Optional Google Calendar text search." }, max_results: limit, page_token: page } } },
    { name: "gcalendar_get_event", description: "Read one event's details from a calendar this user can access. Descriptions and attendee lists are bounded and explicitly marked if shortened. Read-only.",
      inputSchema: { type: "object", additionalProperties: false, properties: { calendar_id: calendar, event_id: { type: "string", maxLength: 1024 } }, required: ["event_id"] } },
    { name: "gcalendar_free_busy", description: "Read availability for up to 25 calendars in an explicit window of at most 31 days. This only queries busy intervals; it never creates, changes, cancels, or invites anyone to a meeting. Calendar ACLs still apply; report per-calendar errors honestly.",
      inputSchema: { type: "object", additionalProperties: false, properties: { time_min: time, time_max: time,
        calendar_ids: { type: "array", minItems: 1, maxItems: 25, items: { type: "string", maxLength: 512 }, description: "Calendar ids; defaults to primary." } }, required: ["time_min", "time_max"] } },
    { name: "gcalendar_gateway_status", description: "Check this user's Calendar connection and account. If reconnection is needed, use the Personal Assistant's Connect/Reconnect prompt. Read-only.",
      inputSchema: { type: "object", additionalProperties: false, properties: {} } },
  ];
}

function text(value, fallback, max) {
  if (value === undefined) return fallback;
  if (typeof value !== "string" || !value.trim() || value.length > max || /[\x00-\x1f\x7f]/.test(value)) throw new Error("invalid_calendar_argument");
  return value.trim();
}
function maxResults(value, config) {
  if (value === undefined) return Math.min(25, config.gcalendar.maxResults);
  if (!Number.isInteger(value) || value < 1 || value > config.gcalendar.maxResults) throw new Error("invalid_max_results");
  return value;
}
function timestamp(value) {
  const input = text(value, null, 40);
  if (!input || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(input)) throw new Error("timestamp_requires_rfc3339_offset");
  const day = new Date(input.slice(0, 10) + "T00:00:00Z");
  const ms = Date.parse(input);
  if (!Number.isFinite(ms) || !Number.isFinite(day.getTime()) || day.toISOString().slice(0, 10) !== input.slice(0, 10)) throw new Error("invalid_timestamp");
  return new Date(ms).toISOString();
}
export function calendarTimeRange(args, maxDays, defaults = false) {
  if (args.page_token && (!args.time_min || !args.time_max)) throw new Error("pagination_requires_original_time_window");
  const timeMin = timestamp(args.time_min ?? (defaults ? new Date().toISOString() : undefined));
  const timeMax = timestamp(args.time_max ?? (defaults ? new Date(Date.parse(timeMin) + 7 * 86400000).toISOString() : undefined));
  const span = Date.parse(timeMax) - Date.parse(timeMin);
  if (span <= 0 || span > maxDays * 86400000) throw new Error("calendar_time_window_out_of_bounds");
  return { timeMin, timeMax };
}
function event(value) {
  const description = String(value.description || "");
  const attendees = Array.isArray(value.attendees) ? value.attendees : [];
  return { id: value.id, status: value.status, summary: value.summary || null,
    description: description.slice(0, 12000), description_complete: description.length <= 12000,
    location: value.location || null, start: value.start || null, end: value.end || null,
    all_day: Boolean(value.start?.date), web_url: value.htmlLink || null,
    organizer: value.organizer || null, attendees: attendees.slice(0, 100), attendees_complete: attendees.length <= 100,
    recurring_event_id: value.recurringEventId || null, original_start: value.originalStartTime || null,
    updated: value.updated || null, conference: value.conferenceData?.entryPoints?.slice(0, 10) || [],
    attachments: value.attachments?.slice(0, 20) || [] };
}

export async function callGcalendarTool({ name, args = {}, config, subject }, { fetchImpl = fetch } = {}) {
  if (!NAMES.has(name)) return { ok: false, error: "Unknown Calendar tool" };
  if (!args || typeof args !== "object" || Array.isArray(args)) return { ok: false, error: "Calendar arguments must be an object." };
  if (!googleConfigured(config, KIND)) return { ok: false, status: "not_configured", error: "Calendar gateway is not configured." };
  if (name === "gcalendar_gateway_status") {
    const state = await getGoogleConnectionState(config, KIND, subject, { fetchImpl });
    return { ok: true, status: state.status, user_connected: Boolean(state.connectionId),
      account_email: state.accountEmail || null, testing_mode: state.testingMode,
      sensitivity: "read-only", assurance: config.gcalendar.assurance };
  }
  const connection = await resolveGoogleConnection(config, KIND, subject, { fetchImpl });
  if (!connection) return { ok: false, error: "Calendar is not connected for this user. Use the Connect/Reconnect prompt in your Personal Assistant." };
  const request = (path, input = {}) => googleProxy(config, KIND, { connection, path, ...input }, { fetchImpl });
  const failure = (response) => ({ ok: false, error: "Calendar request failed. Check your connection and calendar permissions.", status: response.status });
  try {
    const calendarId = text(args.calendar_id, "primary", 512);
    if (name === "gcalendar_list_calendars") {
      const result = await request("/calendar/v3/users/me/calendarList", { query: { maxResults: maxResults(args.max_results, config),
        pageToken: text(args.page_token, undefined, 4096), fields: "items(id,summary,description,timeZone,primary,accessRole),nextPageToken" } });
      if (!result.ok) return failure(result);
      return { ok: true, calendars: result.data.items || [], next_page_token: result.data.nextPageToken || null, complete: !result.data.nextPageToken };
    }
    if (name === "gcalendar_list_events") {
      const range = calendarTimeRange(args, 366, true);
      const result = await request(`/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events`, {
        query: { ...range, singleEvents: true, orderBy: "startTime", maxResults: maxResults(args.max_results, config),
          q: text(args.query, undefined, 500), pageToken: text(args.page_token, undefined, 4096), fields: `items(${EVENT_FIELDS}),nextPageToken,timeZone` } });
      if (!result.ok) return failure(result);
      return { ok: true, calendar_id: calendarId, time_min: range.timeMin, time_max: range.timeMax,
        timezone: result.data.timeZone || null, events: (result.data.items || []).map(event),
        next_page_token: result.data.nextPageToken || null, complete: !result.data.nextPageToken };
    }
    if (name === "gcalendar_get_event") {
      const eventId = text(args.event_id, null, 1024);
      if (!eventId) throw new Error("event_id_required");
      const result = await request(`/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events/${encodeURIComponent(eventId)}`, { query: { fields: EVENT_FIELDS } });
      return result.ok ? { ok: true, calendar_id: calendarId, event: event(result.data) } : failure(result);
    }
    const range = calendarTimeRange(args, 31);
    const ids = args.calendar_ids ?? ["primary"];
    if (!Array.isArray(ids) || ids.length < 1 || ids.length > 25) throw new Error("invalid_calendar_ids");
    const unique = [...new Set(ids.map((id) => text(id, null, 512)))];
    const result = await request("/calendar/v3/freeBusy", { body: { ...range, calendarExpansionMax: 25, items: unique.map((id) => ({ id })) } });
    if (!result.ok) return failure(result);
    const calendars = result.data.calendars || {};
    const groups = result.data.groups || {};
    return { ok: true, time_min: range.timeMin, time_max: range.timeMax, calendars, groups,
      complete: unique.every((id) => calendars[id] || groups[id]) && Object.values(calendars).every((item) => !item.errors?.length)
        && Object.values(groups).every((item) => !item.errors?.length) };
  } catch (error) {
    return { ok: false, error: error.message || "Calendar request could not complete." };
  }
}

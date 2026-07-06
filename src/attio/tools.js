import { createUsageMeter } from "../sharepoint/tools.js";

/**
 * Attio gateway tool registry: read-only reach into the workspace's Attio CRM
 * for managed agents. Sensitivity class: read-only — per the locked connector
 * pattern this gateway never carries write-capable tools.
 *
 * The substrate is Attio's public REST API called DIRECTLY with a
 * single-workspace access token (Bearer, long-lived, scoped read-only at
 * creation). No OAuth broker sits in between on purpose: workspace API keys
 * don't expire or refresh, so a hosted-OAuth layer would add a vendor hop
 * while removing zero steps (same reasoning as the Slack lane). Attio's
 * first-party MCP server (OAuth + DCR) is the future direct-attach lever —
 * recorded in Agent Anything's integration-lanes doc, deliberately not used
 * for the workspace-key case.
 *
 * Tools: attio_search_records, attio_get_record, attio_list_objects,
 * attio_list_lists, attio_list_entries, attio_record_notes,
 * attio_gateway_status.
 */

export { createUsageMeter };

async function attioFetch(config, path, { method = "GET", body = null, query = null } = {}) {
  const key = config.attio.apiKey;
  if (!key) {
    const err = new Error("Attio access token not configured (set ATTIO_API_KEY on the gateway).");
    err.code = "not_configured";
    throw err;
  }
  const url = new URL(`${config.attio.baseUrl}/v2${path}`);
  for (const [k, v] of Object.entries(query || {})) if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${key}`,
      ...(body ? { "content-type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = payload?.message || payload?.error || `attio_http_${res.status}`;
    const err = new Error(`Attio API error (${res.status}): ${message}`);
    err.status = res.status;
    throw err;
  }
  return payload;
}

/* Attio records carry a values map (attribute → array of value objects) that
   is enormous verbatim. Summaries keep the id + the human-legible core so
   agent context stays sane; attio_get_record returns a deeper (still bounded)
   view. */
function firstValue(record, attr) {
  const entry = record?.values?.[attr]?.[0];
  if (!entry) return null;
  return (
    entry.value ??
    entry.full_name ??
    entry.email_address ??
    entry.domain ??
    entry.option?.title ??
    entry.status?.title ??
    entry.currency_value ??
    entry.target_record_id ??
    null
  );
}

function summarizeRecord(record) {
  const values = record?.values || {};
  const summary = {
    record_id: record?.id?.record_id || null,
    object: record?.id?.object_id || null,
    name: firstValue(record, "name"),
    web_url: record?.web_url || null,
    created_at: record?.created_at || null,
  };
  for (const attr of ["email_addresses", "domains", "description", "stage", "value", "owner", "primary_location", "categories", "phone_numbers"]) {
    const v = firstValue(record, attr);
    if (v !== null) summary[attr] = v;
  }
  return summary;
}

function deepRecord(record, maxAttrs = 40) {
  const out = { record_id: record?.id?.record_id || null, web_url: record?.web_url || null, created_at: record?.created_at || null, values: {} };
  const values = record?.values || {};
  for (const [attr, entries] of Object.entries(values).slice(0, maxAttrs)) {
    out.values[attr] = (entries || []).slice(0, 5).map((entry) => {
      const compact = { ...entry };
      delete compact.attribute_type;
      delete compact.created_by_actor;
      return JSON.parse(JSON.stringify(compact).slice(0, 800));
    });
  }
  return out;
}

export function attioToolDefinitions() {
  return [
    {
      name: "attio_search_records",
      description:
        "Search CRM records of one object type by name (contains-match). object is a slug like 'people', 'companies', or 'deals' — call attio_list_objects to discover all slugs including custom objects. Returns compact record summaries with record_id for follow-up calls. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          object: { type: "string", description: "Object slug: people | companies | deals | any custom slug" },
          query: { type: "string", description: "Name text to match (contains)" },
          limit: { type: "number", description: "Max results (default 10, max 25)" },
        },
        required: ["object", "query"],
      },
    },
    {
      name: "attio_get_record",
      description:
        "Read one CRM record in depth: all attributes (bounded), web URL, timestamps. Use after attio_search_records or attio_list_entries. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          object: { type: "string", description: "Object slug the record belongs to" },
          record_id: { type: "string", description: "Record id from a search/list result" },
        },
        required: ["object", "record_id"],
      },
    },
    {
      name: "attio_list_objects",
      description: "List the workspace's CRM object types (standard + custom) with their slugs — the vocabulary for every other tool. Read-only.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "attio_list_lists",
      description: "List the workspace's Attio lists (pipelines/collections) with ids and which object they contain. Read-only.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "attio_list_entries",
      description:
        "List entries of one Attio list (e.g. a sales pipeline): each entry's record summary plus entry values like stage. Use attio_list_lists first for the list id. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          list: { type: "string", description: "List id (or api_slug) from attio_list_lists" },
          limit: { type: "number", description: "Max entries (default 25, max 50)" },
        },
        required: ["list"],
      },
    },
    {
      name: "attio_record_notes",
      description: "Read the notes attached to one CRM record (title + plaintext content, newest first). Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          object: { type: "string", description: "Object slug the record belongs to" },
          record_id: { type: "string", description: "Record id" },
          limit: { type: "number", description: "Max notes (default 10, max 25)" },
        },
        required: ["object", "record_id"],
      },
    },
    {
      name: "attio_gateway_status",
      description:
        "Report the gateway's connection state: whether the workspace access token is configured and which Attio workspace it reaches. Call this first when other attio tools error. Read-only.",
      inputSchema: { type: "object", properties: {} },
    },
  ];
}

const TOOL_NAMES = new Set(attioToolDefinitions().map((tool) => tool.name));

export function isAttioToolName(name) {
  return TOOL_NAMES.has(name);
}

export async function callAttioTool({ name, args = {}, config }) {
  switch (name) {
    case "attio_gateway_status": {
      if (!config.attio.apiKey) {
        return { ok: true, configured: false, note: "No Attio access token configured — an operator sets ATTIO_API_KEY on the gateway." };
      }
      const self = await attioFetch(config, "/self");
      return {
        ok: true,
        configured: true,
        workspace_name: self?.workspace_name || null,
        workspace_id: self?.workspace_id || null,
        assurance: config.attio.assurance,
      };
    }
    case "attio_list_objects": {
      const res = await attioFetch(config, "/objects");
      return {
        ok: true,
        objects: (res.data || []).map((o) => ({ slug: o.api_slug, singular: o.singular_noun, plural: o.plural_noun, id: o.id?.object_id })),
      };
    }
    case "attio_search_records": {
      const object = String(args.object || "").trim();
      const query = String(args.query || "").trim();
      if (!object || !query) return { ok: false, error: "object and query are required" };
      const limit = Math.max(1, Math.min(25, Number(args.limit) || 10));
      const res = await attioFetch(config, `/objects/${encodeURIComponent(object)}/records/query`, {
        method: "POST",
        body: { filter: { name: { $contains: query } }, limit },
      });
      return { ok: true, object, count: (res.data || []).length, records: (res.data || []).map(summarizeRecord) };
    }
    case "attio_get_record": {
      const object = String(args.object || "").trim();
      const recordId = String(args.record_id || "").trim();
      if (!object || !recordId) return { ok: false, error: "object and record_id are required" };
      const res = await attioFetch(config, `/objects/${encodeURIComponent(object)}/records/${encodeURIComponent(recordId)}`);
      return { ok: true, record: deepRecord(res.data || {}) };
    }
    case "attio_list_lists": {
      const res = await attioFetch(config, "/lists");
      return {
        ok: true,
        lists: (res.data || []).map((l) => ({
          list_id: l.id?.list_id,
          slug: l.api_slug,
          name: l.name,
          parent_object: Array.isArray(l.parent_object) ? l.parent_object[0] : l.parent_object,
        })),
      };
    }
    case "attio_list_entries": {
      const list = String(args.list || "").trim();
      if (!list) return { ok: false, error: "list is required" };
      const limit = Math.max(1, Math.min(50, Number(args.limit) || 25));
      const res = await attioFetch(config, `/lists/${encodeURIComponent(list)}/entries/query`, { method: "POST", body: { limit } });
      return {
        ok: true,
        list,
        count: (res.data || []).length,
        entries: (res.data || []).map((e) => ({
          entry_id: e.id?.entry_id,
          parent_record_id: e.parent_record_id,
          parent_object: e.parent_object,
          created_at: e.created_at,
          entry_values: JSON.parse(JSON.stringify(e.entry_values || {}).slice(0, 1200)),
        })),
      };
    }
    case "attio_record_notes": {
      const object = String(args.object || "").trim();
      const recordId = String(args.record_id || "").trim();
      if (!object || !recordId) return { ok: false, error: "object and record_id are required" };
      const limit = Math.max(1, Math.min(25, Number(args.limit) || 10));
      const res = await attioFetch(config, "/notes", { query: { parent_object: object, parent_record_id: recordId, limit } });
      return {
        ok: true,
        count: (res.data || []).length,
        notes: (res.data || []).map((n) => ({
          note_id: n.id?.note_id,
          title: n.title,
          content: String(n.content_plaintext || "").slice(0, 1500),
          created_at: n.created_at,
        })),
      };
    }
    default:
      return { ok: false, error: `Unknown tool: ${name}` };
  }
}

import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

/**
 * SharePoint gateway tool registry: read-only reach into Microsoft SharePoint
 * Online for managed agents. Sensitivity class: read-only — bundled per the
 * locked connector pattern (one gateway per sensitivity class).
 *
 * The substrate is Nango (white-labeled): every call is proxied through Nango's
 * REST proxy to Microsoft Graph (`https://graph.microsoft.com/v1.0/...`), with
 * the connection's OAuth token injected by Nango. Tool names are `sharepoint_*`
 * — Nango never surfaces in the tool surface. Assurance is `observed-l1`
 * (agent-side witnessing) until promoted to attested runtime.
 *
 * Tools: sharepoint_search, sharepoint_list_sites, sharepoint_list_documents,
 * sharepoint_get_document, sharepoint_list_lists, sharepoint_query_list_items,
 * sharepoint_gateway_status.
 */

const GRAPH = "/v1.0";

export function sharepointToolDefinitions(config) {
  const site = config.sharepoint.defaultSiteId;
  return [
    {
      name: "sharepoint_search",
      description:
        "Search the SharePoint document library for files matching a query (filename + content). Returns matching documents with id, name, and web URL. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search text" },
          site_id: { type: "string", description: `SharePoint site id (default: ${site})` }
        },
        required: ["query"]
      }
    },
    {
      name: "sharepoint_list_sites",
      description:
        "List SharePoint sites. With a query, searches sites by name; without one, returns the default (root) site. Read-only.",
      inputSchema: {
        type: "object",
        properties: { query: { type: "string", description: "Optional site-name search" } }
      }
    },
    {
      name: "sharepoint_list_documents",
      description:
        "List documents and folders in a site's default document library, optionally within a folder. Returns name, id, size, type, and web URL. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          site_id: { type: "string", description: `SharePoint site id (default: ${site})` },
          folder_path: { type: "string", description: "Optional folder path within the library, e.g. 'Reports/2026'" }
        }
      }
    },
    {
      name: "sharepoint_get_document",
      description:
        "Read a document's metadata, and its text content when the file is text-like (txt/md/csv/json/html). Binary documents (Word/PDF/Excel) return metadata + a web URL; their text is not extracted. Use sharepoint_list_documents or sharepoint_search to get an item_id. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          item_id: { type: "string", description: "Drive item id of the document" },
          site_id: { type: "string", description: `SharePoint site id (default: ${site})` }
        },
        required: ["item_id"]
      }
    },
    {
      name: "sharepoint_list_lists",
      description: "List the SharePoint lists on a site (id, name, template, web URL). Read-only.",
      inputSchema: {
        type: "object",
        properties: { site_id: { type: "string", description: `SharePoint site id (default: ${site})` } }
      }
    },
    {
      name: "sharepoint_query_list_items",
      description:
        "Read items (with their column fields) from a SharePoint list. Use sharepoint_list_lists to get a list_id. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          list_id: { type: "string", description: "The SharePoint list id" },
          site_id: { type: "string", description: `SharePoint site id (default: ${site})` },
          top: { type: "number", description: "Max items to return (default 25)" }
        },
        required: ["list_id"]
      }
    },
    {
      name: "sharepoint_gateway_status",
      description:
        "Report whether the SharePoint gateway is configured (Nango connection present) and its assurance level. Call this first if other tools return configuration errors.",
      inputSchema: { type: "object", properties: {} }
    }
  ];
}

export async function callSharepointTool({ name, args = {}, config, fetchImpl = fetch }) {
  switch (name) {
    case "sharepoint_search":
      return searchDocuments(args, config, fetchImpl);
    case "sharepoint_list_sites":
      return listSites(args, config, fetchImpl);
    case "sharepoint_list_documents":
      return listDocuments(args, config, fetchImpl);
    case "sharepoint_get_document":
      return getDocument(args, config, fetchImpl);
    case "sharepoint_list_lists":
      return listLists(args, config, fetchImpl);
    case "sharepoint_query_list_items":
      return queryListItems(args, config, fetchImpl);
    case "sharepoint_gateway_status":
      return gatewayStatus(config);
    default:
      return { ok: false, error: `Unknown tool: ${name}` };
  }
}

export function isSharepointToolName(name) {
  return [
    "sharepoint_search",
    "sharepoint_list_sites",
    "sharepoint_list_documents",
    "sharepoint_get_document",
    "sharepoint_list_lists",
    "sharepoint_query_list_items",
    "sharepoint_gateway_status"
  ].includes(name);
}

/* ---------------- tools ---------------- */

function gatewayStatus(config) {
  const sp = config.sharepoint;
  return {
    ok: true,
    status: config.nango.secretKey && sp.connectionId ? "ready" : "not_configured",
    nango_configured: Boolean(config.nango.secretKey),
    connection_configured: Boolean(sp.connectionId),
    provider: sp.providerConfigKey,
    default_site: sp.defaultSiteId,
    assurance: sp.assurance
  };
}

async function listSites(args, config, fetchImpl) {
  const query = String(args.query || "").trim();
  if (query) {
    const { ok, status, data } = await graph(config, { path: `${GRAPH}/sites`, query: { search: query }, fetchImpl });
    if (!ok) return graphError(status, data);
    const sites = (data?.value || []).map(siteSummary);
    return { ok: true, query, sites, site_count: sites.length };
  }
  const { ok, status, data } = await graph(config, { path: `${GRAPH}/sites/${config.sharepoint.defaultSiteId}`, fetchImpl });
  if (!ok) return graphError(status, data);
  return { ok: true, sites: [siteSummary(data)], site_count: 1 };
}

async function listDocuments(args, config, fetchImpl) {
  const site = siteOf(args, config);
  const folder = String(args.folder_path || "").trim().replace(/^\/+|\/+$/g, "");
  const path = folder
    ? `${GRAPH}/sites/${site}/drive/root:/${folder.split("/").map(encodeURIComponent).join("/")}:/children`
    : `${GRAPH}/sites/${site}/drive/root/children`;
  const { ok, status, data } = await graph(config, { path, query: { $top: config.sharepoint.maxItems }, fetchImpl });
  if (!ok) return graphError(status, data);
  const items = (data?.value || []).map(itemSummary);
  return { ok: true, site_id: site, folder: folder || "/", items, item_count: items.length };
}

async function getDocument(args, config, fetchImpl) {
  const site = siteOf(args, config);
  const itemId = String(args.item_id || "").trim();
  if (!itemId) return { ok: false, error: "item_id is required (get one from sharepoint_list_documents or sharepoint_search)" };
  const { ok, status, data } = await graph(config, { path: `${GRAPH}/sites/${site}/drive/items/${encodeURIComponent(itemId)}`, fetchImpl });
  if (!ok) return graphError(status, data);
  const doc = itemSummary(data);
  const downloadUrl = data?.["@microsoft.graph.downloadUrl"];
  const max = config.sharepoint.docMaxChars;
  let content = null;
  let truncated = false;
  let note;

  const isPdf = /pdf/i.test(doc.mime_type || "") || /\.pdf$/i.test(doc.name);
  const isText = isTextLike(doc.name, doc.mime_type);

  if (downloadUrl && (isPdf || isText)) {
    try {
      const res = await fetchImpl(downloadUrl, { signal: AbortSignal.timeout(config.sharepoint.timeoutMs) });
      if (!res.ok) {
        note = `Could not download content (HTTP ${res.status}).`;
      } else if (isPdf) {
        let text = await extractPdfText(await res.arrayBuffer());
        if (text.length > max) {
          text = `${text.slice(0, max)}\n\n[truncated at ${max.toLocaleString()} characters]`;
          truncated = true;
        }
        content = text;
      } else {
        let body = await res.text();
        if (body.length > max) {
          body = `${body.slice(0, max)}\n\n[truncated at ${max.toLocaleString()} characters]`;
          truncated = true;
        }
        content = body;
      }
    } catch (error) {
      note = `Content extraction failed: ${error.message}`;
    }
  } else if (downloadUrl) {
    note = "Binary or unsupported document type (e.g. Word/Excel/PowerPoint); text not extracted. Open it via web_url.";
  }

  return {
    ok: true,
    document: doc,
    content,
    content_available: content != null,
    content_truncated: truncated,
    ...(note ? { note } : {})
  };
}

/* PDF → text via unpdf (pdf.js). Best-effort; the caller degrades to metadata. */
async function extractPdfText(arrayBuffer) {
  const { extractText, getDocumentProxy } = await import("unpdf");
  const pdf = await getDocumentProxy(new Uint8Array(arrayBuffer));
  const { text } = await extractText(pdf, { mergePages: true });
  const body = typeof text === "string" ? text : Array.isArray(text) ? text.join("\n\n") : String(text || "");
  return body.replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
}

async function listLists(args, config, fetchImpl) {
  const site = siteOf(args, config);
  const { ok, status, data } = await graph(config, { path: `${GRAPH}/sites/${site}/lists`, query: { $top: config.sharepoint.maxItems }, fetchImpl });
  if (!ok) return graphError(status, data);
  const lists = (data?.value || []).map((l) => ({
    id: l.id,
    name: l.displayName || l.name || "",
    template: l.list?.template || null,
    web_url: l.webUrl || ""
  }));
  return { ok: true, site_id: site, lists, list_count: lists.length };
}

async function queryListItems(args, config, fetchImpl) {
  const site = siteOf(args, config);
  const listId = String(args.list_id || "").trim();
  if (!listId) return { ok: false, error: "list_id is required (get one from sharepoint_list_lists)" };
  const top = clamp(args.top, 1, config.sharepoint.maxItems, 25);
  const { ok, status, data } = await graph(config, {
    path: `${GRAPH}/sites/${site}/lists/${encodeURIComponent(listId)}/items`,
    query: { $expand: "fields", $top: top },
    fetchImpl
  });
  if (!ok) return graphError(status, data);
  const items = (data?.value || []).map((it) => ({ id: it.id, fields: it.fields || {}, web_url: it.webUrl || "" }));
  return { ok: true, site_id: site, list_id: listId, items, item_count: items.length };
}

async function searchDocuments(args, config, fetchImpl) {
  const site = siteOf(args, config);
  const query = String(args.query || "").trim();
  if (!query) return { ok: false, error: "query is required" };
  const q = encodeURIComponent(query.replace(/'/g, "''")); // escape OData quotes
  const { ok, status, data } = await graph(config, {
    path: `${GRAPH}/sites/${site}/drive/root/search(q='${q}')`,
    query: { $top: config.sharepoint.maxItems },
    fetchImpl
  });
  if (!ok) return graphError(status, data);
  const results = (data?.value || []).map(itemSummary);
  return { ok: true, query, site_id: site, results, result_count: results.length };
}

/* ---------------- Nango → Microsoft Graph ---------------- */

async function graph(config, { method = "GET", path, query = null, fetchImpl = fetch }) {
  const sp = config.sharepoint;
  if (!config.nango.secretKey) return { ok: false, status: 0, data: { error: { message: "NANGO_SECRET_KEY not configured on gateway" } } };
  if (!sp.connectionId) return { ok: false, status: 0, data: { error: { message: "NANGO_SHAREPOINT_CONNECTION_ID not configured on gateway" } } };
  const url = new URL(`${config.nango.serverUrl}/proxy${path}`);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value != null && value !== "") url.searchParams.set(key, String(value));
    }
  }
  let response;
  try {
    response = await fetchImpl(url.toString(), {
      method,
      headers: {
        authorization: `Bearer ${config.nango.secretKey}`,
        "provider-config-key": sp.providerConfigKey,
        "connection-id": sp.connectionId,
        "content-type": "application/json"
      },
      signal: AbortSignal.timeout(sp.timeoutMs)
    });
  } catch (error) {
    return { ok: false, status: 0, data: { error: { message: error.message } } };
  }
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text?.slice(0, 500) };
  }
  return { ok: response.ok, status: response.status, data };
}

/* ---------------- usage metering ---------------- */

export function createUsageMeter(dataDir) {
  const filePath = join(dataDir, "sharepoint-usage.jsonl");
  let dirReady = false;
  const totals = new Map();
  return {
    record({ clientId = "unknown", tool, ok, durationMs = 0 }) {
      const entry = { ts: new Date().toISOString(), client_id: clientId, tool, ok: Boolean(ok), duration_ms: Math.round(durationMs) };
      try {
        if (!dirReady) {
          mkdirSync(dataDir, { recursive: true });
          dirReady = true;
        }
        appendFileSync(filePath, `${JSON.stringify(entry)}\n`, "utf8");
      } catch {
        /* metering must never break a tool call */
      }
      const key = `${entry.client_id}\u0000${tool}`;
      const current = totals.get(key) || { calls: 0, errors: 0 };
      current.calls += 1;
      if (!entry.ok) current.errors += 1;
      totals.set(key, current);
      return entry;
    },
    summarize() {
      const byClient = {};
      for (const [key, value] of totals) {
        const [clientId, tool] = key.split("\u0000");
        byClient[clientId] = byClient[clientId] || {};
        byClient[clientId][tool] = { ...value };
      }
      return byClient;
    },
    filePath
  };
}

/* ---------------- helpers ---------------- */

function siteOf(args, config) {
  return String(args.site_id || config.sharepoint.defaultSiteId).trim();
}

function siteSummary(s = {}) {
  return { id: s.id || "", name: s.displayName || s.name || "", web_url: s.webUrl || "", description: s.description || "" };
}

function itemSummary(i = {}) {
  return {
    id: i.id || "",
    name: i.name || "",
    is_folder: Boolean(i.folder),
    size_bytes: i.size ?? null,
    mime_type: i.file?.mimeType || null,
    web_url: i.webUrl || "",
    last_modified: i.lastModifiedDateTime || null
  };
}

function isTextLike(name = "", mime = "") {
  if (/^(text\/|application\/(json|xml|x-ndjson|csv))/i.test(mime)) return true;
  return /\.(txt|md|markdown|csv|tsv|json|log|xml|ya?ml|html?)$/i.test(name);
}

function clamp(value, min, max, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.round(parsed)));
}

function graphError(status, data) {
  const message =
    data?.error?.message || data?.error?.code || data?.error || data?.message || data?.raw || (status ? `HTTP ${status}` : "request failed");
  return { ok: false, error: `SharePoint/Graph error: ${typeof message === "string" ? message : JSON.stringify(message)}` };
}

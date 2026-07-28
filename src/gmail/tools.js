/**
 * Gmail gateway tools — READ-ONLY (integration-lanes.md Lane 2, manifest #1).
 *
 * Per the locked connector pattern this class never carries write-capable
 * tools: search, read, labels, status. Execution rides Nango's proxy with the
 * CALLER's connection (subject → connection resolved per call); the agent
 * never holds provider credentials. Assurance is declared, not implied:
 * observed-l1 on conventional infrastructure (agent-side witnessing).
 */

import { gmailConfigured, gmailProxy, resolveGmailConnection } from "./client.js";
import { createUsageMeter as createMeter } from "../sharepoint/tools.js";
export const createUsageMeter = (dataDir) => createMeter(dataDir, "gmail-usage.jsonl");

const TOOL_NAMES = new Set(["gmail_search_messages", "gmail_get_message", "gmail_list_labels", "gmail_gateway_status"]);

export function isGmailToolName(name) {
  return TOOL_NAMES.has(name);
}

export function gmailToolDefinitions(config) {
  return [
    {
      name: "gmail_search_messages",
      description:
        "Search the connected Gmail mailbox with a standard Gmail query (from:, to:, subject:, newer_than:, has:attachment, quoted phrases). Returns message ids with subject, sender, date, and snippet. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Gmail search query, e.g. 'from:legal newer_than:7d'" },
          max_results: { type: "number", description: `Max messages to return (default 10, cap ${config.gmail.maxResults})` }
        },
        required: ["query"]
      }
    },
    {
      name: "gmail_get_message",
      description:
        "Read one message by id (from gmail_search_messages): headers (subject, from, to, date) and the message body as text. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          message_id: { type: "string", description: "The Gmail message id" }
        },
        required: ["message_id"]
      }
    },
    {
      name: "gmail_list_labels",
      description: "List the mailbox's labels (system and user). Useful for scoping searches (label:...). Read-only.",
      inputSchema: { type: "object", properties: {} }
    },
    {
      name: "gmail_gateway_status",
      description:
        "Report whether the Gmail gateway is configured and whether the CALLING user has a connected mailbox. Call this first if other tools report connection errors.",
      inputSchema: { type: "object", properties: {} }
    }
  ];
}

export async function callGmailTool({ name, args = {}, config, subject }) {
  if (name === "gmail_gateway_status") return gatewayStatus(config, subject);
  if (!gmailConfigured(config)) {
    return { ok: false, error: "Gmail gateway is not configured (Nango secret or integration key missing)." };
  }
  const connectionId = await resolveGmailConnection(config, subject);
  if (!connectionId) {
    return {
      ok: false,
      error: `No usable Gmail connection for this user (${subject}). Connect or reconnect Gmail from the workspace Connectors screen, then retry.`,
      connect_hint: `${config.publicBaseUrl}/connectors/nango/gmail/status?end_user_id=${encodeURIComponent(subject)}`
    };
  }
  switch (name) {
    case "gmail_search_messages":
      return searchMessages(config, connectionId, args);
    case "gmail_get_message":
      return getMessage(config, connectionId, args);
    case "gmail_list_labels":
      return listLabels(config, connectionId);
    default:
      return { ok: false, error: `Unknown tool: ${name}` };
  }
}

async function gatewayStatus(config, subject) {
  let connectionId = null;
  let resolveError = null;
  if (gmailConfigured(config)) {
    try {
      connectionId = await resolveGmailConnection(config, subject);
    } catch (error) {
      resolveError = error.message;
    }
  }
  return {
    ok: true,
    status: gmailConfigured(config) ? (connectionId ? "ready" : "connection_required") : "not_configured",
    nango_configured: Boolean(config.nango.secretKey),
    integration: config.gmail.providerConfigKey,
    subject,
    user_connected: Boolean(connectionId),
    assurance: config.gmail.assurance,
    sensitivity: "read-only",
    ...(resolveError ? { resolve_error: resolveError } : {})
  };
}

async function searchMessages(config, connectionId, args) {
  const query = String(args.query || "").trim();
  if (!query) return { ok: false, error: "query is required" };
  const max = Math.max(1, Math.min(Number(args.max_results) || 10, config.gmail.maxResults));
  const list = await gmailProxy(config, {
    connectionId,
    path: "/gmail/v1/users/me/messages",
    query: { q: query, maxResults: max }
  });
  if (!list.ok) return proxyError("search", list);
  const ids = (list.data.messages || []).slice(0, max);
  const messages = [];
  for (const item of ids) {
    const meta = await gmailProxy(config, {
      connectionId,
      path: `/gmail/v1/users/me/messages/${item.id}`,
      query: { format: "metadata" }
    });
    const headers = headerMap(meta.data?.payload?.headers);
    messages.push({
      id: item.id,
      thread_id: item.threadId,
      subject: headers.subject || "(no subject)",
      from: headers.from || "",
      date: headers.date || "",
      snippet: meta.data?.snippet || ""
    });
  }
  return { ok: true, query, result_count: messages.length, estimated_total: list.data.resultSizeEstimate ?? null, messages };
}

async function getMessage(config, connectionId, args) {
  const id = String(args.message_id || "").trim();
  if (!id) return { ok: false, error: "message_id is required" };
  const full = await gmailProxy(config, {
    connectionId,
    path: `/gmail/v1/users/me/messages/${id}`,
    query: { format: "full" }
  });
  if (!full.ok) return proxyError("get_message", full);
  const payload = full.data.payload || {};
  const headers = headerMap(payload.headers);
  const body = extractBody(payload).slice(0, config.gmail.bodyMaxChars);
  return {
    ok: true,
    id,
    thread_id: full.data.threadId,
    subject: headers.subject || "(no subject)",
    from: headers.from || "",
    to: headers.to || "",
    cc: headers.cc || undefined,
    date: headers.date || "",
    snippet: full.data.snippet || "",
    body_text: body,
    truncated: extractBody(payload).length > config.gmail.bodyMaxChars
  };
}

async function listLabels(config, connectionId) {
  const res = await gmailProxy(config, { connectionId, path: "/gmail/v1/users/me/labels" });
  if (!res.ok) return proxyError("list_labels", res);
  return {
    ok: true,
    labels: (res.data.labels || []).map((label) => ({ id: label.id, name: label.name, type: label.type }))
  };
}

function proxyError(op, res) {
  const message = res.data?.error?.message || res.data?.message || `status ${res.status}`;
  return { ok: false, error: `Gmail ${op} failed: ${message}`, status: res.status };
}

function headerMap(headers = []) {
  const map = {};
  for (const header of Array.isArray(headers) ? headers : []) {
    map[String(header.name || "").toLowerCase()] = header.value || "";
  }
  return map;
}

/** Prefer text/plain parts; fall back to stripped text/html; walk multiparts. */
function extractBody(payload) {
  const parts = [];
  walk(payload, parts);
  const plain = parts.filter((part) => part.mime === "text/plain").map((part) => part.text).join("\n").trim();
  if (plain) return plain;
  const html = parts.filter((part) => part.mime === "text/html").map((part) => part.text).join("\n");
  return stripHtml(html).trim();
}

function walk(part, out) {
  if (!part) return;
  if (part.body?.data && (part.mimeType === "text/plain" || part.mimeType === "text/html")) {
    out.push({ mime: part.mimeType, text: decodeB64Url(part.body.data) });
  }
  for (const child of part.parts || []) walk(child, out);
}

function decodeB64Url(data) {
  try {
    return Buffer.from(String(data), "base64url").toString("utf8");
  } catch {
    return "";
  }
}

function stripHtml(html) {
  return String(html || "")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\s+/g, " ");
}

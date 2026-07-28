/**
 * Google Drive gateway tools (Lane 2 manifest #4 — mirrors gmail/tools.js).
 *
 * Read-only reach into the CONNECTED USER's own Google Drive: search files,
 * list folders, read file content. Per-user custody — the caller's subject
 * resolves to THEIR Nango connection; one user's agents can never read
 * another's Drive.
 *
 * Content reads are SLICED from birth (the Attio-transcript lesson, learned
 * the same day this gateway was written): gdrive_get_file returns honest
 * coordinates — total_chars, complete, next_start_char — and its description
 * carries the paging protocol, so no agent ever has to summarize a partial
 * read as if it were the whole file.
 */
import { createUsageMeter as createMeter } from "../sharepoint/tools.js";
import { gdriveConfigured, gdriveProxy, getGdriveConnectionState, resolveGdriveConnection } from "./client.js";

export const createUsageMeter = (dataDir) => createMeter(dataDir, "gdrive-usage.jsonl");

/* Google-native types exported to text; everything text-like downloads
   directly; binaries are metadata + link only (honest, not extractable v1). */
const EXPORT_MAP = {
  "application/vnd.google-apps.document": { mime: "text/plain", label: "Google Doc" },
  "application/vnd.google-apps.spreadsheet": { mime: "text/csv", label: "Google Sheet (first tab as CSV)" },
  "application/vnd.google-apps.presentation": { mime: "text/plain", label: "Google Slides" }
};
const TEXT_MIME = /^text\/|^application\/(json|xml|x-yaml|yaml|javascript|x-sh|x-python|sql|csv|markdown)/i;
const DOWNLOAD_SIZE_GUARD = 5 * 1000 * 1000; /* bytes — direct downloads only; Google exports are already bounded */
const FILE_FIELDS = "id,name,mimeType,modifiedTime,size,owners(emailAddress),webViewLink,parents,shortcutDetails";
const LIST_FIELDS = `files(${FILE_FIELDS}),nextPageToken`;

export function gdriveToolDefinitions(config) {
  return [
    {
      name: "gdrive_search_files",
      description:
        "Search the connected user's Google Drive (their own My Drive plus shared drives they can see). Matches file names and full text. Returns compact metadata: id, name, mimeType, modified time, size, owner, web link. Use gdrive_get_file with an id to read content. Read-only, per-user custody.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "What to find — matched against file names and document text." },
          mime_type: { type: "string", description: "Optional exact MIME filter, e.g. application/vnd.google-apps.document (Docs), application/pdf, application/vnd.google-apps.folder." },
          folder_id: { type: "string", description: "Optional: restrict to direct children of this folder id." },
          modified_after: { type: "string", description: "Optional ISO date/datetime — only files modified after this." },
          order_by: { type: "string", enum: ["relevance", "modifiedTime desc", "name"], description: "Sort (default relevance; use 'modifiedTime desc' for recent work)." },
          max_results: { type: "number", description: `Max files (default 15, cap ${config.gdrive.maxResults}).` }
        },
        required: ["query"]
      }
    },
    {
      name: "gdrive_list_folder",
      description:
        "List the contents of one Drive folder (default: My Drive root), folders first then files, newest first. Returns the same compact metadata as search. Use this to browse structure; use gdrive_search_files when you know what you're looking for. Read-only, per-user custody.",
      inputSchema: {
        type: "object",
        properties: {
          folder_id: { type: "string", description: "Folder id (from search/list results). Omit for My Drive root." },
          max_results: { type: "number", description: `Max entries (default 25, cap ${config.gdrive.maxResults}).` }
        }
      }
    },
    {
      name: "gdrive_get_file",
      description:
        "Read one file's metadata and text content, sliced with paging. Google Docs/Sheets/Slides export as text/CSV; text-like files download directly; binaries (PDF, images, Office files) return metadata + web link only — say so rather than guessing their contents. Each call returns one slice plus total_chars, complete, and next_start_char. PROTOCOL for content longer than one slice: keep calling with start_char = next_start_char until complete=true, and NEVER summarize before complete=true — if you stop early, say which part you read. Read-only, per-user custody.",
      inputSchema: {
        type: "object",
        properties: {
          file_id: { type: "string", description: "File id from gdrive_search_files / gdrive_list_folder." },
          start_char: { type: "number", description: "Slice start offset (default 0). For the next slice, pass the previous response's next_start_char." },
          max_chars: { type: "number", description: "Slice size (default 40000, max 60000)." }
        },
        required: ["file_id"]
      }
    },
    {
      name: "gdrive_gateway_status",
      description:
        "Report the Drive gateway's state for the CURRENT user: whether the gateway is configured and whether this user has connected their Google Drive. Call this first when other gdrive tools report connection errors — it tells you whether to send the user to the Connectors screen. Read-only.",
      inputSchema: { type: "object", properties: {} }
    }
  ];
}

const TOOL_NAMES = new Set(["gdrive_search_files", "gdrive_list_folder", "gdrive_get_file", "gdrive_gateway_status"]);

export function isGdriveToolName(name) {
  return TOOL_NAMES.has(name);
}

export async function callGdriveTool({ name, args = {}, config, subject }) {
  if (name === "gdrive_gateway_status") return gatewayStatus(config, subject);
  if (!gdriveConfigured(config)) {
    return { ok: false, error: "Drive gateway is not configured (Nango secret or integration key missing)." };
  }
  const connectionId = await resolveGdriveConnection(config, subject);
  if (!connectionId) {
    return {
      ok: false,
      error: `No usable Google Drive connection for this user (${subject}). Connect or reconnect Google Drive from the workspace Connectors screen, then retry.`,
      connect_hint: `${config.publicBaseUrl}/connectors/nango/gdrive/status?end_user_id=${encodeURIComponent(subject)}`
    };
  }
  switch (name) {
    case "gdrive_search_files":
      return searchFiles(config, connectionId, args);
    case "gdrive_list_folder":
      return listFolder(config, connectionId, args);
    case "gdrive_get_file":
      return getFile(config, connectionId, args);
    default:
      return { ok: false, error: `Unknown tool: ${name}` };
  }
}

async function gatewayStatus(config, subject) {
  if (!gdriveConfigured(config)) {
    return { ok: true, status: "not_configured", nango_configured: false, subject, sensitivity: "read-only" };
  }
  const state = await getGdriveConnectionState(config, subject).catch(() => ({ status: "connection_required", connectionId: null }));
  return {
    ok: true,
    status: state.status,
    nango_configured: true,
    integration: config.gdrive.providerConfigKey,
    subject,
    user_connected: Boolean(state.connectionId),
    assurance: config.gdrive.assurance,
    sensitivity: "read-only"
  };
}

function escapeQ(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

function shapeFile(file) {
  return {
    id: file.id,
    name: file.name,
    mime_type: file.mimeType,
    modified: file.modifiedTime || null,
    size_bytes: file.size ? Number(file.size) : null,
    owner: file.owners?.[0]?.emailAddress || null,
    web_url: file.webViewLink || null,
    is_folder: file.mimeType === "application/vnd.google-apps.folder",
    ...(file.shortcutDetails?.targetId ? { shortcut_target_id: file.shortcutDetails.targetId } : {})
  };
}

function proxyError(op, res) {
  const message = res.data?.error?.message || res.data?.message || `status ${res.status}`;
  return { ok: false, error: `Drive ${op} failed: ${message}`, status: res.status };
}

async function searchFiles(config, connectionId, args) {
  const text = String(args.query || "").trim();
  if (!text) return { ok: false, error: "query is required" };
  const max = Math.max(1, Math.min(Number(args.max_results) || 15, config.gdrive.maxResults));
  const clauses = [`(name contains '${escapeQ(text)}' or fullText contains '${escapeQ(text)}')`, "trashed = false"];
  if (args.mime_type) clauses.push(`mimeType = '${escapeQ(args.mime_type)}'`);
  if (args.folder_id) clauses.push(`'${escapeQ(args.folder_id)}' in parents`);
  if (args.modified_after) clauses.push(`modifiedTime > '${escapeQ(args.modified_after)}'`);
  const res = await gdriveProxy(config, {
    connectionId,
    path: "/drive/v3/files",
    query: {
      q: clauses.join(" and "),
      fields: LIST_FIELDS,
      pageSize: max,
      ...(args.order_by && args.order_by !== "relevance" ? { orderBy: args.order_by } : {}),
      supportsAllDrives: "true",
      includeItemsFromAllDrives: "true",
      corpora: "allDrives"
    }
  });
  if (!res.ok) return proxyError("search", res);
  const files = (res.data.files || []).map(shapeFile);
  return { ok: true, query: text, result_count: files.length, has_more: Boolean(res.data.nextPageToken), files };
}

async function listFolder(config, connectionId, args) {
  const folderId = String(args.folder_id || "root").trim() || "root";
  const max = Math.max(1, Math.min(Number(args.max_results) || 25, config.gdrive.maxResults));
  const res = await gdriveProxy(config, {
    connectionId,
    path: "/drive/v3/files",
    query: {
      q: `'${escapeQ(folderId)}' in parents and trashed = false`,
      fields: LIST_FIELDS,
      pageSize: max,
      orderBy: "folder,modifiedTime desc",
      supportsAllDrives: "true",
      includeItemsFromAllDrives: "true"
    }
  });
  if (!res.ok) return proxyError("list", res);
  const files = (res.data.files || []).map(shapeFile);
  return { ok: true, folder_id: folderId, result_count: files.length, has_more: Boolean(res.data.nextPageToken), files };
}

async function getFile(config, connectionId, args) {
  const fileId = String(args.file_id || "").trim();
  if (!fileId) return { ok: false, error: "file_id is required" };
  const maxChars = Math.max(1000, Math.min(60000, Number(args.max_chars) || 40000));
  const startChar = Math.max(0, Number(args.start_char) || 0);

  const meta = await gdriveProxy(config, {
    connectionId,
    path: `/drive/v3/files/${encodeURIComponent(fileId)}`,
    query: { fields: FILE_FIELDS, supportsAllDrives: "true" }
  });
  if (!meta.ok) return proxyError("get", meta);
  const file = shapeFile(meta.data);

  /* Shortcuts resolve to their target so agents don't dead-end. */
  if (meta.data.mimeType === "application/vnd.google-apps.shortcut" && file.shortcut_target_id) {
    return getFile(config, connectionId, { ...args, file_id: file.shortcut_target_id });
  }
  if (file.is_folder) {
    return { ok: true, file, content: null, note: "This is a folder — use gdrive_list_folder with this id." };
  }

  let text = null;
  let extraction = null;
  const exportSpec = EXPORT_MAP[meta.data.mimeType];
  if (exportSpec) {
    const exp = await gdriveProxy(config, {
      connectionId,
      path: `/drive/v3/files/${encodeURIComponent(fileId)}/export`,
      query: { mimeType: exportSpec.mime },
      raw: true
    });
    if (!exp.ok) return { ok: false, error: `Drive export failed (status ${exp.status}) — the file may be too large to export (10MB export cap).`, file };
    text = exp.text;
    extraction = `exported ${exportSpec.label} as ${exportSpec.mime}`;
  } else if (TEXT_MIME.test(meta.data.mimeType || "")) {
    if (file.size_bytes && file.size_bytes > DOWNLOAD_SIZE_GUARD) {
      return { ok: true, file, content: null, note: `File is ${file.size_bytes} bytes — beyond this tool's ${DOWNLOAD_SIZE_GUARD}-byte direct-read guard. Open the web link, or ask for a specific smaller export.` };
    }
    const dl = await gdriveProxy(config, {
      connectionId,
      path: `/drive/v3/files/${encodeURIComponent(fileId)}`,
      query: { alt: "media", supportsAllDrives: "true" },
      raw: true
    });
    if (!dl.ok) return { ok: false, error: `Drive download failed (status ${dl.status})`, file };
    text = dl.text;
    extraction = `downloaded ${meta.data.mimeType}`;
  } else {
    return {
      ok: true,
      file,
      content: null,
      note: `Binary or non-exportable type (${meta.data.mimeType}) — content is not extractable through this tool. Share what the metadata says and point the user at web_url; do not guess the contents.`
    };
  }

  /* Sliced read with honest coordinates — the transcript-paging protocol. */
  const slice = text.slice(startChar, startChar + maxChars);
  const endChar = startChar + slice.length;
  const complete = endChar >= text.length;
  return {
    ok: true,
    file,
    extraction,
    content: slice,
    start_char: startChar,
    end_char: endChar,
    total_chars: text.length,
    complete,
    next_start_char: complete ? null : endChar,
    note: complete ? undefined : `Slice ${startChar}-${endChar} of ${text.length} total chars. Call again with start_char=${endChar}; summarize only after complete=true.`
  };
}

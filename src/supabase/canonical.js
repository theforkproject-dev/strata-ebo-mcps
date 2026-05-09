import { digestValue } from "../strata/primitives.js";

export const SUPABASE_ACTION_CERTIFICATE_VERSION = "strata.supabase.mcp_action_certificate.v1";
export const SUPABASE_ACTION_REGISTRY_VERSION = "strata.action-registry.supabase.v1";
export const SUPABASE_CONNECTOR_MANIFEST_VERSION = "strata.supabase.connector_manifest.v1";
export const SUPABASE_POLICY_DECISION_VERSION = "strata.supabase.policy_decision.v1";

const READONLY_VERBS = new Set(["select", "with", "explain"]);
const BLOCKED_TOKENS = [
  "insert",
  "update",
  "delete",
  "merge",
  "upsert",
  "alter",
  "drop",
  "create",
  "truncate",
  "grant",
  "revoke",
  "copy",
  "call",
  "do",
  "notify",
  "listen",
  "unlisten",
  "begin",
  "commit",
  "rollback",
  "savepoint",
  "set"
];

export function connectorManifest(config) {
  return {
    version: SUPABASE_CONNECTOR_MANIFEST_VERSION,
    connector_id: config.supabase.connectorId,
    connector_label: config.supabase.connectorLabel,
    connector_type: "supabase_mcp",
    upstream: {
      origin: upstreamOrigin(config),
      base_url: config.supabase.mcpBaseUrl,
      project_ref: config.supabase.projectRef || null,
      read_only: config.supabase.readOnly,
      features: config.supabase.features
    },
    evidence_mode: config.supabase.evidenceMode,
    constraints: {
      max_rows: config.supabase.maxRows,
      timeout_ms: config.supabase.timeoutMs,
      blocked_schemas: config.supabase.blockedSchemas,
      blocked_tables: config.supabase.blockedTables
    },
    tools: [
      manifestTool("supabase_list_tables_verified", "execute_sql", "database.metadata.read", "supabase.list_tables.v1"),
      manifestTool("supabase_inspect_schema_verified", "execute_sql", "database.metadata.read", "supabase.schema.inspect.v1"),
      manifestTool("supabase_query_readonly_verified", "execute_sql", "database.read", "supabase.query.v1"),
      manifestTool("supabase_search_docs", "search_docs", "docs.read", "supabase.docs.search.v1")
    ]
  };
}

export function connectorManifestDigest(config) {
  return digestValue(connectorManifest(config));
}

export function upstreamMcpUrl(config) {
  const url = new URL(config.supabase.mcpBaseUrl);
  if (config.supabase.projectRef) {
    url.searchParams.set("project_ref", config.supabase.projectRef);
  }
  url.searchParams.set("read_only", String(Boolean(config.supabase.readOnly)));
  if (config.supabase.features.length > 0) {
    url.searchParams.set("features", config.supabase.features.join(","));
  }
  return url.toString();
}

export function upstreamOrigin(config) {
  try {
    return new URL(config.supabase.mcpBaseUrl).origin;
  } catch {
    return "";
  }
}

export function credentialFingerprint(config, credential = {}) {
  const source = credential.refresh_token || credential.access_token || config.supabase.oauth.refreshToken || config.supabase.oauth.accessToken || "";
  return source ? `sha256:${digestValue({ credential: source })}` : null;
}

export function canonicalSupabaseRequest({ strataToolName, upstreamToolName, upstreamArguments, input, config }) {
  return {
    version: "strata.supabase.request.v1",
    connector_id: config.supabase.connectorId,
    project_ref: config.supabase.projectRef,
    read_only: config.supabase.readOnly,
    features: config.supabase.features,
    strata_tool_name: strataToolName,
    upstream_tool_name: upstreamToolName,
    upstream_arguments: upstreamArguments,
    input
  };
}

export function classifyReadOnlySql(sql, config) {
  const errors = [];
  const normalized = normalizeSql(sql);
  const statements = splitStatements(normalized);
  if (statements.length !== 1) {
    errors.push("exactly one SQL statement is required");
  }
  const first = firstToken(statements[0] || normalized);
  if (!READONLY_VERBS.has(first)) {
    errors.push(`SQL must start with SELECT, WITH, or EXPLAIN; got ${first || "empty"}`);
  }
  for (const token of BLOCKED_TOKENS) {
    if (containsToken(normalized, token)) {
      errors.push(`SQL token is not allowed in read-only phase: ${token.toUpperCase()}`);
    }
  }
  for (const schema of config.supabase.blockedSchemas || []) {
    if (schema && containsSchemaReference(normalized, schema)) {
      errors.push(`schema is blocked by connector policy: ${schema}`);
    }
  }
  for (const table of config.supabase.blockedTables || []) {
    if (table && normalized.includes(table.toLowerCase())) {
      errors.push(`table is blocked by connector policy: ${table}`);
    }
  }
  return {
    ok: errors.length === 0,
    normalized_sql: normalized,
    sql_digest: digestValue({ sql: normalized }),
    first_token: first,
    statement_count: statements.length,
    errors
  };
}

export function enforceLimit(sql, maxRows) {
  const normalized = normalizeSql(sql);
  if (containsToken(normalized, "limit")) {
    return normalized;
  }
  return `${normalized.replace(/;$/, "")} limit ${maxRows}`;
}

export function summarizeSupabaseResult(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value ?? null);
  const parsedRows = tryExtractRows(value);
  return {
    version: "strata.supabase.result_summary.v1",
    result_digest: digestValue(value ?? null),
    result_text_digest: digestValue({ text }),
    result_bytes: Buffer.byteLength(text, "utf8"),
    row_count: parsedRows ? parsedRows.length : null,
    evidence_mode: "digest-only"
  };
}

export function redactSupabaseResult(value, maxChars = 1200) {
  const text = typeof value === "string" ? value : JSON.stringify(value ?? null, null, 2);
  return text.length > maxChars ? `${text.slice(0, maxChars)}\n...[truncated]` : text;
}

export function supabaseToolResultPayload(value, { mode = "summary", maxChars = 20000 } = {}) {
  if (!value || mode === "summary") {
    return null;
  }
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  const truncated = text.length > maxChars;
  return {
    version: "strata.supabase.tool_result_payload.v1",
    mode,
    truncated,
    bytes: Buffer.byteLength(text, "utf8"),
    text: truncated ? `${text.slice(0, maxChars)}\n...[truncated]` : text,
    json: mode === "full-json" && !truncated && typeof value !== "string" ? value : null,
    note: "This live MCP response payload is intentionally not included in the durable certificate bundle, which remains digest-only."
  };
}

function manifestTool(strataTool, upstreamTool, policyClass, certificateProfile) {
  return {
    strata_tool: strataTool,
    upstream_tool: upstreamTool,
    policy_class: policyClass,
    canonicalizer: certificateProfile,
    certificate_profile: certificateProfile,
    human_approval_required: false
  };
}

function normalizeSql(sql) {
  return String(sql || "").replace(/--.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\s+/g, " ").trim().toLowerCase();
}

function splitStatements(sql) {
  return sql.split(";").map((item) => item.trim()).filter(Boolean);
}

function firstToken(sql) {
  const match = String(sql || "").trim().match(/^([a-z_]+)/i);
  return match ? match[1].toLowerCase() : "";
}

function containsToken(sql, token) {
  return new RegExp(`\\b${escapeRegExp(token)}\\b`, "i").test(sql);
}

function containsSchemaReference(sql, schema) {
  return new RegExp(`\\b${escapeRegExp(schema.toLowerCase())}\\s*\\.`, "i").test(sql);
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function tryExtractRows(value) {
  if (Array.isArray(value)) {
    return value;
  }
  if (Array.isArray(value?.result)) {
    return value.result;
  }
  if (typeof value?.result === "string") {
    const match = value.result.match(/<untrusted-data-[^>]+>\s*([\s\S]*?)\s*<\/untrusted-data-[^>]+>/);
    const candidate = match ? match[1] : value.result;
    try {
      const parsed = JSON.parse(candidate);
      return Array.isArray(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }
  return null;
}

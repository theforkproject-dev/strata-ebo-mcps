import { rpcError } from "./jsonrpc.js";
import { callGmailTool, createUsageMeter, gmailToolDefinitions, isGmailToolName } from "./gmail/tools.js";

/**
 * Strata Gmail MCP Gateway — the read-only Gmail capability (search, read,
 * labels via the Gmail REST API, executed through Nango with the CALLER's own
 * connection) behind one governed, metered MCP endpoint. Lane 2 of
 * integration-lanes.md: the generic Nango bridge, Gmail as manifest #1.
 *
 * Per-user custody: each caller's OAuth client_name carries their subject
 * (`aa:<org>:<userId>`); the gateway resolves subject → Nango connection per
 * call. One user's threads can never read another's mailbox — the credential
 * is the boundary, exactly like memory. Assurance declared, not implied:
 * observed-l1 (agent-side witnessing) until promoted to attested runtime.
 */
export class GmailMcpServer {
  constructor(config, { resolveClientName = null } = {}) {
    this.config = config;
    this.serverName = "strata-gmail-mcp-gateway";
    this.serverTitle = "Strata Gmail MCP Gateway";
    this.meter = createUsageMeter(config.dataDir);
    this.resolveClientName = resolveClientName;
  }

  async dispatch(request, requestContext = {}) {
    switch (request.method) {
      case "initialize":
        return this.initialize(request.params || {}, requestContext);
      case "ping":
        return {};
      case "tools/list":
        return { tools: gmailToolDefinitions(this.config) };
      case "tools/call":
        return this.callTool(request.params || {}, requestContext);
      case "resources/list":
        return { resources: [] };
      case "resources/read":
        throw rpcError(-32602, `Resource not found: ${request.params?.uri}`);
      default:
        throw rpcError(-32601, `Method not found: ${request.method}`);
    }
  }

  initialize(params, requestContext) {
    const requested = params.protocolVersion;
    const protocolVersion = requested && requested < "2025-11-25" ? requested : "2025-11-25";
    return {
      protocolVersion,
      capabilities: {
        tools: { listChanged: false },
        resources: { listChanged: false }
      },
      serverInfo: { name: this.serverName, title: this.serverTitle, version: "0.1.0" },
      instructions:
        "Read-only Gmail tools for the CONNECTED USER's own mailbox. gmail_search_messages finds messages with a Gmail query; gmail_get_message reads one (headers + text body); gmail_list_labels lists labels. Call gmail_gateway_status first if tools report connection errors — it says whether this user has connected their mailbox. All calls are metered per client and witnessed by the calling platform.",
      _meta: {
        session_id: requestContext.session?.sid,
        assurance: this.config.gmail.assurance
      }
    };
  }

  async callTool(params, requestContext = {}) {
    const name = params.name;
    const args = params.arguments || {};
    if (!isGmailToolName(name)) {
      return toolResult({ ok: false, error: `Unknown tool: ${name}` }, true);
    }

    const subject = await this.subjectFromContext(requestContext);
    const startedAt = Date.now();
    let payload;
    try {
      payload = await callGmailTool({ name, args, config: this.config, subject });
    } catch (error) {
      payload = { ok: false, error: error.message };
    }

    this.meter.record({
      clientId: subject,
      tool: name,
      ok: payload.ok !== false,
      durationMs: Date.now() - startedAt
    });

    return toolResult(payload, payload.ok === false);
  }

  /** The caller's subject: OAuth client_name (per-mint identity from Agent
   *  Anything, `aa:<org>:<userId>`) resolved from the session's client id;
   *  falls back to the raw client id, then the session agent id. */
  async subjectFromContext(requestContext = {}) {
    const session = requestContext.session || {};
    const clientId = session.oauthClientId || session.aid || session.clientId || null;
    if (clientId && this.resolveClientName) {
      try {
        const name = await this.resolveClientName(clientId);
        if (name) return name;
      } catch {
        /* fall through to ids */
      }
    }
    return clientId || session.agentId || "unknown";
  }

  usageSummary() {
    return this.meter.summarize();
  }
}

function toolResult(structuredContent, isError = false) {
  return {
    content: [{ type: "text", text: JSON.stringify(structuredContent, null, 2) }],
    structuredContent,
    isError
  };
}

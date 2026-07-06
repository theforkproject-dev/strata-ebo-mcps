import { rpcError } from "./jsonrpc.js";
import { attioToolDefinitions, callAttioTool, createUsageMeter, isAttioToolName } from "./attio/tools.js";

/**
 * Strata Attio MCP Gateway — the read-only CRM capability pack (records,
 * lists, notes via Attio's REST API with a workspace access token) behind one
 * governed, metered MCP endpoint. Sensitivity class: read-only; per the
 * locked connector pattern this class never carries write-capable tools.
 *
 * Assurance level is declared, not implied: `observed-l1` on conventional
 * infrastructure (agent-side witnessing). Mirrors SharepointMcpServer.
 */
export class AttioMcpServer {
  constructor(config) {
    this.config = config;
    this.serverName = "strata-attio-mcp-gateway";
    this.serverTitle = "Strata Attio MCP Gateway";
    this.meter = createUsageMeter(config.dataDir, "attio-usage.jsonl");
  }

  async dispatch(request, requestContext = {}) {
    switch (request.method) {
      case "initialize":
        return this.initialize(request.params || {}, requestContext);
      case "ping":
        return {};
      case "tools/list":
        return { tools: attioToolDefinitions() };
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
      serverInfo: {
        name: this.serverName,
        title: this.serverTitle,
        version: "0.1.0"
      },
      instructions:
        "Read-only Attio CRM tools. Start with attio_list_objects to learn the workspace's object slugs, then attio_search_records (name contains-match) and attio_get_record for depth; attio_list_lists / attio_list_entries for pipelines; attio_record_notes for a record's notes. Call attio_gateway_status if tools report configuration errors. All calls are metered per client and witnessed by the calling platform.",
      _meta: {
        session_id: requestContext.session?.sid,
        assurance: this.config.attio.assurance
      }
    };
  }

  async callTool(params, requestContext = {}) {
    const name = params.name;
    const args = params.arguments || {};

    if (!isAttioToolName(name)) {
      return toolResult({ ok: false, error: `Unknown tool: ${name}` }, true);
    }

    const startedAt = Date.now();
    let payload;
    try {
      payload = await callAttioTool({ name, args, config: this.config });
    } catch (error) {
      payload = { ok: false, error: error.message };
    }

    this.meter.record({
      clientId: clientIdFromContext(requestContext),
      tool: name,
      ok: payload.ok !== false,
      durationMs: Date.now() - startedAt
    });

    return toolResult(payload, payload.ok === false);
  }

  usageSummary() {
    return this.meter.summarize();
  }
}

function clientIdFromContext(requestContext = {}) {
  const session = requestContext.session || {};
  return session.oauthClientId || session.clientId || session.oauth?.client_id || session.agentId || "unknown";
}

function toolResult(structuredContent, isError = false) {
  return {
    content: [{ type: "text", text: JSON.stringify(structuredContent, null, 2) }],
    structuredContent,
    isError
  };
}

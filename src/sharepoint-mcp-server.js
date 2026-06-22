import { rpcError } from "./jsonrpc.js";
import {
  callSharepointTool,
  createUsageMeter,
  isSharepointToolName,
  sharepointToolDefinitions
} from "./sharepoint/tools.js";

/**
 * Strata SharePoint MCP Gateway — the read-only SharePoint capability pack
 * (search, list, and read documents + lists via Microsoft Graph, proxied
 * through Nango) behind one governed, metered MCP endpoint. Sensitivity class:
 * read-only; per the locked connector pattern this class never carries
 * write-capable tools.
 *
 * Assurance level is declared, not implied: `observed-l1` on conventional
 * infrastructure (agent-side witnessing), `attested-l1` once promoted to
 * attested runtime. Consumers read it from sharepoint_gateway_status and the
 * connector catalog. Mirrors ResearchMcpServer (same read-only shape).
 */
export class SharepointMcpServer {
  constructor(config) {
    this.config = config;
    this.serverName = "strata-sharepoint-mcp-gateway";
    this.serverTitle = "Strata SharePoint MCP Gateway";
    this.meter = createUsageMeter(config.dataDir);
  }

  async dispatch(request, requestContext = {}) {
    switch (request.method) {
      case "initialize":
        return this.initialize(request.params || {}, requestContext);
      case "ping":
        return {};
      case "tools/list":
        return { tools: sharepointToolDefinitions(this.config) };
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
        "Read-only SharePoint tools. Use sharepoint_search to find documents by query, sharepoint_list_sites / sharepoint_list_documents / sharepoint_list_lists to browse, sharepoint_get_document to read a document's contents, and sharepoint_query_list_items for structured SharePoint list data. Call sharepoint_gateway_status if tools report configuration errors. All calls are metered per client and witnessed by the calling platform.",
      _meta: {
        session_id: requestContext.session?.sid,
        assurance: this.config.sharepoint.assurance
      }
    };
  }

  async callTool(params, requestContext = {}) {
    const name = params.name;
    const args = params.arguments || {};

    if (!isSharepointToolName(name)) {
      return toolResult({ ok: false, error: `Unknown tool: ${name}` }, true);
    }

    const startedAt = Date.now();
    let payload;
    try {
      payload = await callSharepointTool({ name, args, config: this.config });
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

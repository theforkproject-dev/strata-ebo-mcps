import { rpcError } from "./jsonrpc.js";
import {
  callResearchTool,
  createUsageMeter,
  isResearchToolName,
  researchToolDefinitions
} from "./research/tools.js";

/**
 * Strata Research MCP Gateway — the read-only research capability pack
 * (Firecrawl, Perplexity, X search via OpenRouter) behind one governed,
 * metered MCP endpoint. Sensitivity class: read-only; per the locked
 * connector pattern this class never carries write-capable tools.
 *
 * Assurance level is declared, not implied: `observed-l1` while deployed on
 * conventional infrastructure (agent-side witnessing only), `attested-l1`
 * once promoted to attested runtime. Consumers read it from
 * research_gateway_status and the connector catalog.
 */
export class ResearchMcpServer {
  constructor(config) {
    this.config = config;
    this.serverName = "strata-research-mcp-gateway";
    this.serverTitle = "Strata Research MCP Gateway";
    this.meter = createUsageMeter(config.dataDir);
  }

  async dispatch(request, requestContext = {}) {
    switch (request.method) {
      case "initialize":
        return this.initialize(request.params || {}, requestContext);
      case "ping":
        return {};
      case "tools/list":
        return { tools: researchToolDefinitions(this.config) };
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
        "Read-only research tools. Use perplexity_ask for synthesized answers with citations, firecrawl_search/perplexity_search for ranked results, firecrawl_scrape to read a specific page, and x_search for X/Twitter-focused questions. Call research_gateway_status if tools report configuration errors. All calls are metered per client and witnessed by the calling platform.",
      _meta: {
        session_id: requestContext.session?.sid,
        assurance: this.config.research.assurance
      }
    };
  }

  async callTool(params, requestContext = {}) {
    const name = params.name;
    const args = params.arguments || {};

    if (!isResearchToolName(name)) {
      return toolResult({ ok: false, error: `Unknown tool: ${name}` }, true);
    }

    const startedAt = Date.now();
    let payload;
    try {
      payload = await callResearchTool({ name, args, config: this.config });
    } catch (error) {
      payload = { ok: false, error: error.message };
    }

    this.meter.record({
      clientId: clientIdFromContext(requestContext),
      tool: name,
      ok: payload.ok !== false,
      durationMs: Date.now() - startedAt,
      vendorUsage: payload.usage || null
    });

    return toolResult(payload, payload.ok === false);
  }

  usageSummary() {
    return this.meter.summarize();
  }
}

function clientIdFromContext(requestContext = {}) {
  const session = requestContext.session || {};
  return (
    session.oauthClientId ||
    session.clientId ||
    session.oauth?.client_id ||
    session.agentId ||
    "unknown"
  );
}

function toolResult(structuredContent, isError = false) {
  return {
    content: [{ type: "text", text: JSON.stringify(structuredContent, null, 2) }],
    structuredContent,
    isError
  };
}

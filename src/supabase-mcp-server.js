import { rpcError } from "./jsonrpc.js";
import { createSupabaseActionRegistry, runVerifiedSupabaseAction, supabaseGatewayStatus } from "./strata/verified-supabase.js";

export class SupabaseMcpServer {
  constructor(config) {
    this.config = config;
    this.serverName = "strata-supabase-mcp-gateway";
    this.serverTitle = "Strata Supabase MCP Governance Proxy";
    this.actionRegistryPromise = null;
    this.latestCertificate = null;
  }

  async dispatch(request, requestContext = {}) {
    switch (request.method) {
      case "initialize":
        return this.initialize(request.params || {}, requestContext);
      case "ping":
        return {};
      case "tools/list":
        return { tools: (await this.getActionRegistry()).tools };
      case "tools/call":
        return this.callTool(request.params || {}, requestContext);
      case "resources/list":
        return { resources: this.listResources() };
      case "resources/read":
        return this.readResource(request.params?.uri);
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
      instructions: "Use gateway_status before Supabase tools. The assistant sees curated Strata tools only; the gateway maps approved calls to Supabase MCP with project_ref, read_only, and features constraints.",
      _meta: {
        session_id: requestContext.session?.sid
      }
    };
  }

  async callTool(params, requestContext = {}) {
    const name = params.name;
    const args = params.arguments || {};
    try {
      if (name === "gateway_status") {
        const structuredContent = await supabaseGatewayStatus(this.config);
        return toolResult(structuredContent, structuredContent.status !== "ready");
      }

      if (isSupabaseToolName(name)) {
        const run = await runVerifiedSupabaseAction({ toolName: normalizeSupabaseToolName(name), input: args, config: this.config, requestContext });
        if (run.certificate_ref) {
          this.latestCertificate = run;
        }
        return toolResult(run, !run.ok);
      }

      return toolResult({ error: `Unknown tool: ${name}` }, true);
    } catch (error) {
      return toolResult({ error: error.message }, true);
    }
  }

  listResources() {
    const resources = [
      {
        uri: "strata://action-registry/current",
        name: "current-action-registry",
        title: "Current Supabase MCP Action Registry",
        description: "MCP projection of the Strata Supabase governance proxy action registry.",
        mimeType: "application/json"
      }
    ];
    if (this.latestCertificate) {
      resources.push({
        uri: "strata://certificate/latest",
        name: "latest-certificate",
        title: "Latest Supabase MCP Certificate",
        description: "Artifact references and digest metadata for the latest Supabase MCP action.",
        mimeType: "application/json"
      });
    }
    return resources;
  }

  async readResource(uri) {
    if (uri === "strata://action-registry/current") {
      return resource(uri, await this.getActionRegistry());
    }
    if (uri === "strata://certificate/latest" && this.latestCertificate) {
      return resource(uri, this.latestCertificate);
    }
    throw rpcError(-32602, `Resource not found: ${uri}`);
  }

  async getActionRegistry() {
    if (!this.actionRegistryPromise) {
      this.actionRegistryPromise = createSupabaseActionRegistry(this.config);
    }
    try {
      return await this.actionRegistryPromise;
    } catch (error) {
      this.actionRegistryPromise = null;
      throw error;
    }
  }
}

function isSupabaseToolName(name) {
  return String(name || "").startsWith("supabase_") || String(name || "").startsWith("supabase.");
}

function normalizeSupabaseToolName(name) {
  return String(name || "").replace(/^supabase\./, "supabase_");
}

function toolResult(structuredContent, isError = false) {
  return {
    content: [{ type: "text", text: JSON.stringify(structuredContent, null, 2) }],
    structuredContent,
    isError
  };
}

function resource(uri, value) {
  return {
    contents: [{
      uri,
      mimeType: "application/json",
      text: JSON.stringify(value, null, 2)
    }]
  };
}

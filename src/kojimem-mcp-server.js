import { rpcError } from "./jsonrpc.js";
import { createKojimemActionRegistry, kojimemGatewayStatus, runVerifiedKojimemHandoff } from "./strata/verified-kojimem.js";
import { KOJIMEM_MCP_TOOL } from "./kojimem/canonical.js";

export class KojimemMcpServer {
  constructor(config) {
    this.config = config;
    this.serverName = "strata-kojimem-agent-handoff-gateway";
    this.serverTitle = "Attexa Kojimem Agent Handoff Gateway";
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
      instructions: "Use gateway_status before fraud_signal_exchange_verified. This gateway executes a live Kojimem x402 agent-to-agent backpack handoff with Attexa L1/L2 evidence and optional L3 domain attestation.",
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
        const structuredContent = await kojimemGatewayStatus(this.config);
        return toolResult(structuredContent, structuredContent.status !== "ready");
      }

      if (name === KOJIMEM_MCP_TOOL || name === "agent_handoff.fraud_signal_exchange") {
        const run = await runVerifiedKojimemHandoff({ input: args, config: this.config, requestContext });
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
        title: "Current Kojimem Agent Handoff Action Registry",
        description: "MCP projection of the Attexa Kojimem agent handoff gateway action registry.",
        mimeType: "application/json"
      }
    ];
    if (this.latestCertificate) {
      resources.push({
        uri: "strata://certificate/latest",
        name: "latest-certificate",
        title: "Latest Kojimem Agent Handoff Certificate",
        description: "Artifact references and digest metadata for the latest witnessed Kojimem handoff.",
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
      this.actionRegistryPromise = createKojimemActionRegistry(this.config);
    }
    try {
      return await this.actionRegistryPromise;
    } catch (error) {
      this.actionRegistryPromise = null;
      throw error;
    }
  }
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

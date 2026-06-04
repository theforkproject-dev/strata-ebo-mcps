import { nangoMcpJsonRpc, resolveNangoSupabaseConnection } from "./client.js";

export class NangoSupabaseMcpClient {
  constructor(config, { fetchImpl = fetch, requestContext = {} } = {}) {
    this.config = config;
    this.fetchImpl = fetchImpl;
    this.requestContext = requestContext;
    this.nextId = 1;
    this.initialized = false;
    this.connectionBinding = null;
    this.mcpSessionId = "";
  }

  async listTools() {
    await this.initialize();
    return this.rpc("tools/list", {});
  }

  async callTool(name, args = {}) {
    await this.initialize();
    return this.rpc("tools/call", { name, arguments: args });
  }

  async initialize() {
    if (this.initialized) return;
    try {
      await this.rpc("initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: {
          name: "attexa-nango-supabase-mcp-gateway",
          version: "0.1.0"
        }
      });
      await this.notify("notifications/initialized", {});
    } catch (error) {
      if (!String(error.message || "").includes("Method not found")) {
        throw error;
      }
    }
    this.initialized = true;
  }

  async rpc(method, params) {
    return this.sendJsonRpc({ jsonrpc: "2.0", id: this.nextId++, method, params }, { expectResult: true });
  }

  async notify(method, params) {
    await this.sendJsonRpc({ jsonrpc: "2.0", method, params }, { expectResult: false });
  }

  async sendJsonRpc(payload, { expectResult }) {
    const binding = await this.connection();
    const result = await nangoMcpJsonRpc(this.config, binding.connection_id, payload, {
      projectRef: binding.project_ref,
      mcpSessionId: this.mcpSessionId,
      onSession: (sessionId) => {
        this.mcpSessionId = sessionId;
      },
      fetchImpl: this.fetchImpl
    });
    return expectResult ? result : null;
  }

  async connection() {
    if (!this.connectionBinding) {
      const binding = await resolveNangoSupabaseConnection(this.config, this.requestContext);
      if (!binding.ok) {
        const missing = binding.missing?.length ? ` Missing: ${binding.missing.join(", ")}.` : "";
        throw new Error(`Nango Supabase connection is not authorized. Open ${binding.connect_url} to connect Supabase.${missing}`);
      }
      this.connectionBinding = binding;
    }
    return this.connectionBinding;
  }
}

import { rpcError } from "./jsonrpc.js";
import { callGcalendarTool, createUsageMeter, gcalendarToolDefinitions, isGcalendarToolName } from "./gcalendar/tools.js";

export class GcalendarMcpServer {
  constructor(config, { resolveClientName = null } = {}) {
    this.config = config;
    this.serverName = "strata-gcalendar-mcp-gateway";
    this.serverTitle = "Google Calendar — read-only";
    this.resolveClientName = resolveClientName;
    this.meter = createUsageMeter(config.dataDir);
  }
  async dispatch(request, requestContext = {}) {
    switch (request.method) {
      case "initialize": return {
        protocolVersion: request.params?.protocolVersion && request.params.protocolVersion < "2025-11-25" ? request.params.protocolVersion : "2025-11-25",
        capabilities: { tools: { listChanged: false }, resources: { listChanged: false } },
        serverInfo: { name: this.serverName, title: this.serverTitle, version: "0.1.0" },
        instructions: "Read-only Calendar tools use this user's own Google connection. List calendars and read events/availability subject to their Google permissions. Follow pagination until complete=true before claiming a complete schedule. You cannot create, edit, cancel, or invite attendees to events.",
      };
      case "ping": return {};
      case "tools/list": return { tools: gcalendarToolDefinitions(this.config) };
      case "tools/call": return this.callTool(request.params || {}, requestContext);
      case "resources/list": return { resources: [] };
      default: throw rpcError(-32601, `Method not found: ${request.method}`);
    }
  }
  async callTool(params, context) {
    if (!isGcalendarToolName(params.name)) return result({ ok: false, error: "Unknown Calendar tool" });
    const clientId = context.session?.oauthClientId || context.session?.aid || context.session?.clientId;
    let subject = null;
    if (clientId && this.resolveClientName) subject = await this.resolveClientName(clientId);
    const started = Date.now(); let payload;
    try { payload = await callGcalendarTool({ name: params.name, args: params.arguments || {}, config: this.config, subject }); }
    catch (error) { payload = { ok: false, error: error.code || "Calendar connection unavailable." }; }
    this.meter.record({ clientId: subject || "unbound", tool: params.name, ok: payload.ok !== false, durationMs: Date.now() - started });
    return result(payload);
  }
  usageSummary() { return this.meter.summarize(); }
}

function result(value) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }], structuredContent: value, isError: value.ok === false };
}

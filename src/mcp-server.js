import { createActionRegistry, gatewayStatus, previewEmail, runVerifiedEmailSend, verifyReceivedEmail } from "./strata/verified-email.js";
import { rpcError } from "./jsonrpc.js";

export const MCP_PROTOCOL_VERSION = "2025-11-25";

export class EmailMcpServer {
  constructor(config) {
    this.config = config;
    this.actionRegistry = createActionRegistry(config);
    this.latestCertificate = null;
    this.latestRecipientVerification = null;
  }

  async dispatch(request, requestContext = {}) {
    switch (request.method) {
      case "initialize":
        return this.initialize(request.params || {}, requestContext);
      case "ping":
        return {};
      case "tools/list":
        return { tools: this.actionRegistry.tools };
      case "tools/call":
        return this.callTool(request.params || {});
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
    const protocolVersion = requested && requested < MCP_PROTOCOL_VERSION ? requested : MCP_PROTOCOL_VERSION;
    return {
      protocolVersion,
      capabilities: {
        tools: { listChanged: false },
        resources: { listChanged: false }
      },
      serverInfo: {
        name: "strata-email-mcp",
        title: "Strata Verified Email MCP Server",
        version: "0.1.0"
      },
      instructions: "Use tools/list to discover gateway_status, email_preview, email_send_verified, and email_verify_received. email_send_verified is gated by Strata Level 1 mechanical witnesses and Level 2 policy witnesses.",
      _meta: {
        session_id: requestContext.session?.sid
      }
    };
  }

  async callTool(params) {
    const name = params.name;
    const args = params.arguments || {};

    try {
      if (name === "email_preview" || name === "email.preview") {
        const structuredContent = previewEmail(args, this.config);
        return toolResult(structuredContent);
      }

      if (name === "gateway_status") {
        const structuredContent = await gatewayStatus(this.config);
        return toolResult(structuredContent, structuredContent.status !== "ready");
      }

      if (name === "email_send_verified" || name === "email.send_verified") {
        const run = await runVerifiedEmailSend(args, this.config);
        if (run.certificate_ref) {
          this.latestCertificate = run;
        }
        const structuredContent = {
          status: run.denied ? "policy_denied" : (run.ok ? "sent" : "verification_failed"),
          denial_stage: run.denial_stage,
          provider: run.tool_output?.provider || null,
          provider_message_id: run.tool_output?.provider_message_id || null,
          provider_status: run.tool_output?.provider_status || null,
          certificate_ref: run.certificate_ref,
          certificate_url: run.certificate_url,
          certificate_digest: run.certificate_digest,
          action_id: run.tool_output?.action_id || null,
          action_id_semantics: "pre-send IntentGrant grant_id authorizing this exact email send",
          payload_digest: run.commitment.payload_digest,
          witness_quorum: "2-of-3",
          verification_tiers: ["level-1-mechanical", "level-2-policy"],
          policy_quorum: run.policy_quorum,
          receipt_count: run.receipt_count,
          checkpoint_id: run.checkpoint_id,
          receipt_root: run.final_state_root,
          verified: run.ok,
          certificate_transmission: run.certificate_transmission,
          receipt_flow: run.receipt_flow,
          artifacts: run.artifacts,
          errors: run.errors
        };
        return toolResult(structuredContent, !run.ok);
      }

      if (name === "email_verify_received" || name === "email.verify_received") {
        const result = verifyReceivedEmail(args, this.config);
        this.latestRecipientVerification = result;
        return toolResult({
          status: result.receipt.result,
          receipt_ref: `file://${result.receipt_path}`,
          receipt: result.receipt
        }, result.receipt.result !== "valid");
      }

      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error: ${error.message}` }],
        isError: true
      };
    }
  }

  listResources() {
    const resources = [
      {
        uri: "strata://action-registry/current",
        name: "current-action-registry",
        title: "Current Verified Email Action Registry",
        description: "MCP projection of the local Strata email action registry.",
        mimeType: "application/json"
      }
    ];
    if (this.latestCertificate) {
      resources.push({
        uri: "strata://certificate/latest",
        name: "latest-certificate",
        title: "Latest Verified Email Certificate",
        description: "Artifact references and digest metadata for the latest verified email send.",
        mimeType: "application/json"
      });
    }
    if (this.latestRecipientVerification) {
      resources.push({
        uri: "strata://recipient-verification/latest",
        name: "latest-recipient-verification",
        title: "Latest Recipient Verification Receipt",
        description: "Recipient-side verification receipt for a received email.",
        mimeType: "application/json"
      });
    }
    return resources;
  }

  readResource(uri) {
    if (uri === "strata://action-registry/current") {
      return resource(uri, this.actionRegistry);
    }
    if (uri === "strata://certificate/latest" && this.latestCertificate) {
      return resource(uri, this.latestCertificate);
    }
    if (uri === "strata://recipient-verification/latest" && this.latestRecipientVerification) {
      return resource(uri, this.latestRecipientVerification);
    }
    throw rpcError(-32602, `Resource not found: ${uri}`);
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

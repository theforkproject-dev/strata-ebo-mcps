import {
  capabilityDigest,
  createToolExecutionReceiptObject,
  digestValue,
  signReceipt,
  toolRequestDigest,
  verifyCapability
} from "../strata/primitives.js";
import { summarizeSupabaseResult } from "./canonical.js";

export function createSupabaseTool({ signer, gatewayKeyring, client, clock = () => new Date() }) {
  const consumedTokenIds = new Set();
  const executions = [];

  return {
    name: "supabase-mcp",
    audience: "supabase-mcp",
    method: "MCP tools/call",
    executions,

    async execute({ token, request, requestDigest, prevStateRoot, sessionId, stepIndex, intentGrantRef = null }) {
      const expectedDigest = toolRequestDigest({
        toolAudience: "supabase-mcp",
        method: "MCP tools/call",
        request
      });
      if (requestDigest !== expectedDigest) {
        throw new Error("Tool request digest does not match request payload");
      }

      const verification = verifyCapability(token, gatewayKeyring, {
        audience: "supabase-mcp",
        method: "MCP tools/call",
        requestDigest,
        now: clock().toISOString()
      });
      if (!verification.ok) {
        throw new Error(`Capability rejected: ${verification.errors.join("; ")}`);
      }
      if (consumedTokenIds.has(token.claims.token_id)) {
        throw new Error("Capability token has already been consumed");
      }
      consumedTokenIds.add(token.claims.token_id);

      let upstreamResult = null;
      let upstreamError = null;
      try {
        upstreamResult = await client.callTool(request.upstream_tool_name, request.upstream_arguments || {});
      } catch (error) {
        upstreamError = error.message;
      }

      const resultSummary = upstreamResult ? summarizeSupabaseResult(upstreamResult) : null;
      const output = {
        version: "strata.supabase.execution_output.v1",
        status: upstreamError ? "error" : "completed",
        action_id: token.claims.grant_id,
        connector_id: request.connector_id,
        project_ref: request.project_ref,
        strata_tool_name: request.strata_tool_name,
        upstream_tool_name: request.upstream_tool_name,
        certificate_url: request.certificate_url || null,
        result: resultSummary,
        upstream_error: upstreamError,
        // Returned to the active MCP turn only; certificate bundles persist result digests, not this payload.
        upstream_result_live: upstreamResult
      };
      executions.push(output);

      const outputDigest = digestValue(output);
      const receipt = signReceipt({
        kind: "tool.execution",
        session_id: sessionId,
        step_index: stepIndex,
        prev_state_root: prevStateRoot,
        actor: { type: "tool", id: "supabase-mcp" },
        body: {
          token_digest: capabilityDigest(token),
          intent_grant_ref: intentGrantRef,
          method: "MCP tools/call",
          request_digest: requestDigest,
          output_digest: outputDigest,
          evidence_ref: `supabase-mcp://${request.connector_id}/${request.upstream_tool_name}`,
          tool_execution_receipt: createToolExecutionReceiptObject({
            intentGrantRef,
            requestReceivedAt: clock().toISOString(),
            requestCanonicalHash: requestDigest,
            response: {
              status: upstreamError ? "error" : "ok",
              response_commitment: outputDigest,
              error: upstreamError
            },
            idempotencyKey: token.claims.idempotency_key,
            toolKeyId: signer.keyId
          })
        },
        issued_at: clock().toISOString()
      }, signer);

      return { output, receipt };
    }
  };
}

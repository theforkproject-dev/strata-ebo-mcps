import {
  capabilityDigest,
  createToolExecutionReceiptObject,
  digestValue,
  signReceipt,
  toolRequestDigest,
  verifyCapability
} from "../strata/primitives.js";
import { emailCommitment } from "./canonical.js";

export function createEmailTool({ signer, gatewayKeyring, provider, clock = () => new Date() }) {
  const consumedTokenIds = new Set();
  const executions = [];

  return {
    name: "email-api",
    audience: "email-api",
    method: "POST /v1/send-email",
    executions,

    async execute({ token, request, requestDigest, prevStateRoot, sessionId, stepIndex, intentGrantRef = null }) {
      const expectedDigest = toolRequestDigest({
        toolAudience: "email-api",
        method: "POST /v1/send-email",
        request
      });
      if (requestDigest !== expectedDigest) {
        throw new Error("Tool request digest does not match request payload");
      }

      const verification = verifyCapability(token, gatewayKeyring, {
        audience: "email-api",
        method: "POST /v1/send-email",
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

      const { publicCommitment } = emailCommitment(request.email);
      const headers = {
        "X-Strata-Action-Id": token.claims.grant_id,
        "X-Strata-Payload-Digest": publicCommitment.payload_digest,
        "X-Strata-Certificate-URL": request.certificate_url,
        "X-Strata-Witness-Tier": "level-1-mechanical"
      };
      const providerResult = await provider.send({ canonical: request.email, headers });
      const output = {
        version: "strata.email.execution_output.v1",
        status: "sent",
        action_id: token.claims.grant_id,
        provider: providerResult.provider,
        provider_message_id: providerResult.message_id,
        provider_status: providerResult.status,
        sent_at: providerResult.sent_at,
        certificate_url: request.certificate_url,
        commitment: publicCommitment,
        headers_committed: providerResult.headers_committed
      };
      executions.push(output);

      const outputDigest = digestValue(output);
      const receipt = signReceipt({
        kind: "tool.execution",
        session_id: sessionId,
        step_index: stepIndex,
        prev_state_root: prevStateRoot,
        actor: { type: "tool", id: "email-api" },
        body: {
          token_digest: capabilityDigest(token),
          intent_grant_ref: intentGrantRef,
          method: "POST /v1/send-email",
          request_digest: requestDigest,
          output_digest: outputDigest,
          evidence_ref: `provider://${providerResult.provider}/messages/${providerResult.message_id}`,
          tool_execution_receipt: createToolExecutionReceiptObject({
            intentGrantRef,
            requestReceivedAt: clock().toISOString(),
            requestCanonicalHash: requestDigest,
            response: {
              status: "ok",
              response_commitment: outputDigest,
              error: null
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

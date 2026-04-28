import { capabilityDigest, verifyCapability } from "../capability.js";
import { digestValue, toolRequestDigest } from "../digests.js";
import { signReceipt } from "../receipt.js";
import { createToolExecutionReceiptObject } from "../schemas/v0_3.js";

export function createPaymentsTool({ signer, gatewayKeyring, clock = () => new Date() }) {
  const consumedTokenIds = new Set();
  const executions = [];

  return {
    name: "payments-api",
    audience: "payments-api",
    method: "POST /v1/payments",
    executions,

    async execute({ token, request, requestDigest, prevStateRoot, sessionId, stepIndex, intentGrantRef = null }) {
      const expectedDigest = toolRequestDigest({
        toolAudience: "payments-api",
        method: "POST /v1/payments",
        request
      });

      if (requestDigest !== expectedDigest) {
        throw new Error("Tool request digest does not match request payload");
      }

      const verification = verifyCapability(token, gatewayKeyring, {
        audience: "payments-api",
        method: "POST /v1/payments",
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

      const paymentId = `pay_${digestValue({ request, token_id: token.claims.token_id }).slice(0, 16)}`;
      const output = {
        payment_id: paymentId,
        status: "created",
        amount: request.amount,
        currency: request.currency,
        recipient: request.recipient
      };
      executions.push(output);

      const outputDigest = digestValue(output);
      const receipt = signReceipt({
        kind: "tool.execution",
        session_id: sessionId,
        step_index: stepIndex,
        prev_state_root: prevStateRoot,
        actor: { type: "tool", id: "payments-api" },
        body: {
          token_digest: capabilityDigest(token),
          intent_grant_ref: intentGrantRef,
          method: "POST /v1/payments",
          request_digest: requestDigest,
          output_digest: outputDigest,
          evidence_ref: `tool://payments-api/executions/${paymentId}`,
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

export function createLegacyPaymentsTool({ signer, clock = () => new Date() }) {
  const executions = [];

  return {
    name: "legacy-payments-api",
    audience: "legacy-payments-api",
    method: "POST /v1/payments",
    certified: false,
    executions,

    async execute({ token, request, requestDigest, prevStateRoot, sessionId, stepIndex, intentGrantRef = null }) {
      const paymentId = `legacy_pay_${digestValue({ request, requestDigest }).slice(0, 16)}`;
      const output = {
        payment_id: paymentId,
        status: "created",
        amount: request.amount,
        currency: request.currency,
        recipient: request.recipient
      };
      executions.push(output);

      const outputDigest = digestValue(output);
      const receipt = signReceipt({
        kind: "tool.execution",
        session_id: sessionId,
        step_index: stepIndex,
        prev_state_root: prevStateRoot,
        actor: { type: "tool", id: "legacy-payments-api" },
        body: {
          token_digest: capabilityDigest(token),
          intent_grant_ref: intentGrantRef,
          method: "POST /v1/payments",
          request_digest: requestDigest,
          output_digest: outputDigest,
          evidence_ref: `tool://legacy-payments-api/executions/${paymentId}`,
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
          }),
          certification: {
            tool_verified_capability: false,
            taint_label: "uncertified_tool"
          }
        },
        issued_at: clock().toISOString()
      }, signer);

      return { output, receipt };
    }
  };
}

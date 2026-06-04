import {
  capabilityDigest,
  createToolExecutionReceiptObject,
  digestValue,
  signReceipt,
  toolRequestDigest,
  verifyCapability
} from "../strata/primitives.js";
import { axiosErrorMessage } from "./client.js";
import {
  KOJIMEM_EXECUTION_OUTPUT_VERSION,
  KOJIMEM_GATEWAY_METHOD,
  KOJIMEM_GATEWAY_TOOL,
  summarizeExecutionOutput
} from "./canonical.js";

export function createKojimemHandoffTool({ signer, gatewayKeyring, agentAClient, agentBClient, clock = () => new Date() }) {
  const consumedTokenIds = new Set();
  const executions = [];

  return {
    name: KOJIMEM_GATEWAY_TOOL,
    audience: KOJIMEM_GATEWAY_TOOL,
    method: KOJIMEM_GATEWAY_METHOD,
    executions,

    async execute({ token, request, requestDigest, prevStateRoot, sessionId, stepIndex, intentGrantRef = null }) {
      const expectedDigest = toolRequestDigest({
        toolAudience: KOJIMEM_GATEWAY_TOOL,
        method: KOJIMEM_GATEWAY_METHOD,
        request
      });
      if (requestDigest !== expectedDigest) {
        throw new Error("Tool request digest does not match request payload");
      }

      const verification = verifyCapability(token, gatewayKeyring, {
        audience: KOJIMEM_GATEWAY_TOOL,
        method: KOJIMEM_GATEWAY_METHOD,
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

      const output = await executeHandoff({ request, agentAClient, agentBClient, actionId: token.claims.grant_id, clock });
      executions.push(output);

      const outputDigest = digestValue(output);
      const receipt = signReceipt({
        kind: "tool.execution",
        session_id: sessionId,
        step_index: stepIndex,
        prev_state_root: prevStateRoot,
        actor: { type: "tool", id: KOJIMEM_GATEWAY_TOOL },
        body: {
          token_digest: capabilityDigest(token),
          intent_grant_ref: intentGrantRef,
          method: KOJIMEM_GATEWAY_METHOD,
          request_digest: requestDigest,
          output_digest: outputDigest,
          evidence_ref: output.memory_id ? `kojimem://${output.memory_id}` : "kojimem://handoff/error",
          tool_execution_receipt: createToolExecutionReceiptObject({
            intentGrantRef,
            requestReceivedAt: clock().toISOString(),
            requestCanonicalHash: requestDigest,
            response: {
              status: output.status === "completed" ? "ok" : "error",
              response_commitment: outputDigest,
              error: output.error || null
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

async function executeHandoff({ request, agentAClient, agentBClient, actionId, clock }) {
  let memory = null;
  let delegation = null;
  let recall = null;
  let destroy = null;
  const startedAt = clock().toISOString();
  try {
    memory = await agentAClient.createMemory({
      persona: request.execution.persona,
      ttl: request.execution.ttl,
      instructions: request.execution.instructions
    });
    await agentAClient.writeFacts(memory.id, request.execution.facts);
    delegation = await agentAClient.createDelegation(memory.id, {
      delegate: request.delegation.delegate_wallet,
      actions: request.delegation.actions,
      max_tier: request.delegation.max_tier
    });
    recall = await agentBClient.recall(memory.id, {
      question: request.execution.recall_question,
      tier: request.recall.tier,
      delegation: delegation.delegation
    });
    destroy = await agentBClient.destroy(memory.id, { delegation: delegation.delegation });

    const answer = String(recall.answer || "");
    return {
      version: KOJIMEM_EXECUTION_OUTPUT_VERSION,
      status: "completed",
      action_id: actionId,
      started_at: startedAt,
      completed_at: clock().toISOString(),
      memory_id: memory.id,
      memory: {
        id: memory.id,
        persona: memory.persona,
        expires_at: memory.expires_at,
        owner_wallet: memory.wallet
      },
      agents: request.agents,
      data: {
        data_class: request.backpack.data_class,
        fact_count: request.backpack.fact_count,
        facts_digest: request.backpack.facts_digest
      },
      delegation: {
        delegation_hash: delegation.delegation_hash,
        delegate: delegation.delegate,
        scope: request.delegation.actions,
        expires_at: delegation.expires_at,
        header_digest: digestValue(delegation.delegation)
      },
      recall: {
        tier: recall.tier || request.recall.tier,
        question_digest: request.recall.question_digest,
        answer_digest: digestValue(answer),
        answer_preview: answer.slice(0, 700)
      },
      destroy,
      settlement: {
        network: "Base Sepolia",
        protocol: "x402",
        asset: "USDC",
        total_usdc_estimate: "0.015",
        paid_by: {
          create_memory: request.agents.originator.wallet,
          recall: request.agents.delegate.wallet
        }
      },
      summary: null,
      error: null
    };
  } catch (error) {
    const message = axiosErrorMessage(error);
    if (memory?.id) {
      try {
        await agentAClient.destroy(memory.id);
      } catch {
        // Best-effort cleanup; preserve the primary failure.
      }
    }
    const output = {
      version: KOJIMEM_EXECUTION_OUTPUT_VERSION,
      status: "error",
      action_id: actionId,
      started_at: startedAt,
      completed_at: clock().toISOString(),
      memory_id: memory?.id || null,
      memory: memory ? { id: memory.id, persona: memory.persona, expires_at: memory.expires_at, owner_wallet: memory.wallet } : null,
      agents: request.agents,
      delegation: delegation ? { delegation_hash: delegation.delegation_hash, delegate: delegation.delegate } : null,
      recall: recall ? { tier: recall.tier || request.recall.tier, answer_digest: digestValue(String(recall.answer || "")) } : null,
      destroy,
      settlement: {
        network: "Base Sepolia",
        protocol: "x402",
        asset: "USDC",
        total_usdc_estimate: "partial"
      },
      error: message
    };
    output.summary = summarizeExecutionOutput(output);
    return output;
  }
}

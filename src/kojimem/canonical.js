import { digestValue } from "../strata/primitives.js";

export const KOJIMEM_REQUEST_VERSION = "strata.kojimem.agent_handoff_request.v1";
export const KOJIMEM_EXECUTION_OUTPUT_VERSION = "strata.kojimem.execution_output.v1";
export const KOJIMEM_ACTION_CERTIFICATE_VERSION = "strata.kojimem.agent_handoff_certificate.v1";
export const KOJIMEM_POLICY_DECISION_VERSION = "strata.kojimem.policy_decision.v1";
export const KOJIMEM_ACTION_REGISTRY_VERSION = "strata.kojimem.action_registry.v1";

export const KOJIMEM_WORKFLOW_ID = "agent-handoff.fraud-signal-exchange";
export const KOJIMEM_GATEWAY_TOOL = "kojimem-agent-handoff";
export const KOJIMEM_GATEWAY_METHOD = "POST /v1/agent-handoff/fraud-signal-exchange";
export const KOJIMEM_MCP_TOOL = "fraud_signal_exchange_verified";

export function defaultFraudSignals() {
  return [
    "Volume anomaly: BIN 411111 logged 47 card-not-present authorization requests at one merchant in 8 minutes; expected baseline is 2 to 4 per hour.",
    "Geographic distribution: 38 of the 47 requests originated from IP ranges in 3 networks recently flagged for elevated declines.",
    "Amount ladder: requested values stepped from $0.99 to $4.99 to $99.99 within the cluster, a pattern consistent with low-value validation followed by higher-value attempts.",
    "Card cohort: 12 of the cards in the cluster were issued in a single batch in Q4 2025, suggesting the cohort was sourced together.",
    "Decline reasons: 41 of 47 requests were declined for CVV2 mismatch, indicating the requestors did not have access to the security codes."
  ];
}

export function defaultRecallQuestion() {
  return "Given these issuer-side observations, characterize the cluster pattern, estimate likely cross-issuer exposure, and outline appropriate network-level review steps.";
}

export function normalizeHandoffInput(input = {}, config) {
  const facts = Array.isArray(input.facts) && input.facts.length > 0
    ? input.facts.map((item) => String(item))
    : defaultFraudSignals();
  const recallTier = normalizeTier(input.recall_tier || config.kojimem.defaultRecallTier || "reasoning");
  const estimatedExposureUsd = Number(input.estimated_exposure_usd ?? config.kojimem.defaultEstimatedExposureUsd ?? 25000);
  return {
    scenario_id: String(input.scenario_id || "eta-fraud-signal-exchange"),
    scenario_title: String(input.scenario_title || "Agent-to-Agent Fraud Signal Exchange"),
    data_class: String(input.data_class || "issuer_fraud_signals"),
    persona: String(input.persona || "research"),
    ttl: String(input.ttl || config.kojimem.defaultTtl || "1h"),
    facts,
    recall_question: String(input.recall_question || defaultRecallQuestion()),
    recall_tier: recallTier,
    delegation_actions: normalizeActions(input.delegation_actions || ["recall", "destroy"]),
    estimated_exposure_usd: Number.isFinite(estimatedExposureUsd) ? estimatedExposureUsd : 25000,
    case_id: String(input.case_id || "FRD-ETA-2026-001"),
    agent_a_label: String(input.agent_a_label || config.kojimem.agentALabel || "Conduit - Issuer Fraud Analyst"),
    agent_b_label: String(input.agent_b_label || config.kojimem.agentBLabel || "Sentinel - Network Correlator"),
    l3_attestation: input.l3_attestation || null
  };
}

export function createKojimemHandoffRequest(input = {}, config) {
  const normalized = normalizeHandoffInput(input, config);
  const agentA = config.kojimem.agentAAccount;
  const agentB = config.kojimem.agentBAccount;
  const factsDigest = digestValue(normalized.facts);
  const questionDigest = digestValue(normalized.recall_question);
  const request = {
    version: KOJIMEM_REQUEST_VERSION,
    workflow_id: KOJIMEM_WORKFLOW_ID,
    scenario_id: normalized.scenario_id,
    scenario_title: normalized.scenario_title,
    case_id: normalized.case_id,
    agents: {
      originator: {
        label: normalized.agent_a_label,
        wallet: agentA?.address || null,
        role: "issuer_fraud_analyst"
      },
      delegate: {
        label: normalized.agent_b_label,
        wallet: agentB?.address || null,
        role: "network_correlator"
      }
    },
    backpack: {
      persona: normalized.persona,
      ttl: normalized.ttl,
      data_class: normalized.data_class,
      fact_count: normalized.facts.length,
      facts_digest: factsDigest
    },
    delegation: {
      delegate_wallet: agentB?.address || null,
      actions: normalized.delegation_actions,
      max_tier: normalized.recall_tier,
      open_delegation: isOpenDelegation(agentB?.address)
    },
    recall: {
      tier: normalized.recall_tier,
      question_digest: questionDigest
    },
    execution: removeUndefined({
      persona: normalized.persona,
      ttl: normalized.ttl,
      facts: normalized.facts,
      recall_question: normalized.recall_question,
      instructions: normalized.instructions || undefined
    }),
    risk: {
      estimated_exposure_usd: normalized.estimated_exposure_usd,
      cross_organization: true,
      requires_policy_review: true
    }
  };
  return {
    request,
    executionInput: normalized,
    publicCommitment: {
      version: "strata.kojimem.public_commitment.v1",
      workflow_id: KOJIMEM_WORKFLOW_ID,
      request_digest: digestValue(request),
      facts_digest: factsDigest,
      fact_count: normalized.facts.length,
      recall_question_digest: questionDigest,
      estimated_exposure_usd: normalized.estimated_exposure_usd,
      agent_a_wallet: agentA?.address || null,
      agent_b_wallet: agentB?.address || null,
      l3_attestation_digest: normalized.l3_attestation ? digestValue(normalized.l3_attestation) : null
    }
  };
}

export function createKojimemConnectorManifest(config) {
  return {
    version: "strata.kojimem.connector_manifest.v1",
    connector_id: config.kojimem.connectorId,
    connector_label: config.kojimem.connectorLabel,
    connector_type: "kojimem_x402_backpack",
    upstream: {
      base_url: config.kojimem.apiBaseUrl,
      network: config.kojimem.network,
      settlement_asset: "USDC",
      payment_protocol: "x402"
    },
    agents: {
      originator: {
        label: config.kojimem.agentALabel,
        wallet: config.kojimem.agentAAccount?.address || null
      },
      delegate: {
        label: config.kojimem.agentBLabel,
        wallet: config.kojimem.agentBAccount?.address || null
      }
    },
    tools: [
      {
        strata_tool: KOJIMEM_MCP_TOOL,
        gateway_tool: KOJIMEM_GATEWAY_TOOL,
        policy_class: "agentic_financial_data_handoff",
        certificate_profile: KOJIMEM_ACTION_CERTIFICATE_VERSION
      }
    ]
  };
}

export function connectorManifestDigest(config) {
  return digestValue(createKojimemConnectorManifest(config));
}

export function summarizeExecutionOutput(output = {}) {
  return {
    status: output.status || "unknown",
    memory_id: output.memory_id || null,
    delegation_hash: output.delegation?.delegation_hash || null,
    delegation_scope: output.delegation?.scope || null,
    recall_tier: output.recall?.tier || null,
    recall_answer_digest: output.recall?.answer_digest || null,
    recall_answer_preview: output.recall?.answer_preview || null,
    destroyed: output.destroy?.ok || false,
    settlement: output.settlement || null,
    error: output.error || null
  };
}

export function l3AttestationSummary(attestation) {
  if (!attestation) return null;
  return {
    attestation_id: attestation.attestation_id || null,
    attestor_id: attestation.attestor_id || null,
    claim_type: attestation.claim_type || null,
    decision: attestation.decision || null,
    request_digest: attestation.request_digest || null,
    issued_at: attestation.issued_at || null,
    signature_digest: attestation.signature ? digestValue(attestation.signature) : null
  };
}

function normalizeTier(value) {
  return ["fast", "balanced", "reasoning"].includes(String(value)) ? String(value) : "reasoning";
}

function normalizeActions(value) {
  const actions = Array.isArray(value) ? value.map(String) : ["recall", "destroy"];
  return [...new Set(actions)].sort();
}

function isOpenDelegation(address) {
  return String(address || "").toLowerCase() === "0x0000000000000000000000000000000000000a11";
}

function removeUndefined(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}

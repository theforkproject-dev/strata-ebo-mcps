export const PROTOCOL_DOMAINS = Object.freeze({
  SESSION_START: "turnstile.session-start.v1",
  ACTION: "turnstile.action.v1",
  INTENT_GRANT: "turnstile.intent-grant.v1",
  TOOL_EXECUTION: "turnstile.tool-execution.v1",
  OBSERVATION: "turnstile.observation.v1",
  ABORT: "turnstile.abort.v1",
  CHECKPOINT: "turnstile.checkpoint.v1",
  SESSION_END: "turnstile.session-end.v1",
  DISSENT_NOTICE: "turnstile.dissent-notice.v1",
  SESSION_REFERENCE: "turnstile.session-reference.v1"
});

export function createSessionStartObject({
  sessionId,
  governanceId = null,
  governancePolicyHash,
  witnessSetId = null,
  witnessSetEpoch = 0,
  agentAttestationRef = null,
  gatewayAttestationRef = null,
  verifierAttestationRef = null,
  admissionManifestHash = null,
  verifierProfileHash = null,
  crossSessionReferenceDigests = [],
  startTime,
  initialInputsCommitment = null
}) {
  return {
    domain: PROTOCOL_DOMAINS.SESSION_START,
    session_id: sessionId,
    governance_id: governanceId,
    governance_policy_hash: governancePolicyHash,
    witness_set_id: witnessSetId,
    witness_set_epoch: witnessSetEpoch,
    agent_attestation_ref: agentAttestationRef,
    gateway_attestation_ref: gatewayAttestationRef,
    verifier_attestation_ref: verifierAttestationRef,
    admission_manifest_hash: admissionManifestHash,
    verifier_profile_hash: verifierProfileHash,
    cross_session_reference_digests: crossSessionReferenceDigests,
    start_time: startTime,
    initial_inputs_commitment: initialInputsCommitment
  };
}

export function createActionReceiptObject({
  sessionId,
  stepIndex,
  prevReceiptHash,
  actionType,
  actionManifest,
  observation,
  gatewayKeyId = null,
  emittedAt
}) {
  return {
    domain: PROTOCOL_DOMAINS.ACTION,
    session_id: sessionId,
    step_index: stepIndex,
    prev_receipt_hash: prevReceiptHash,
    action_type: actionType,
    action_manifest: actionManifest,
    observation,
    gateway_key_id: gatewayKeyId,
    emitted_at: emittedAt
  };
}

export function createIntentGrantObject({
  sessionId,
  stepIndex,
  prevReceiptHash,
  toolId,
  audience,
  method,
  canonicalRequestHash,
  typedArgsDigest,
  typedInputs = [],
  capabilityToken
}) {
  return {
    domain: PROTOCOL_DOMAINS.INTENT_GRANT,
    session_id: sessionId,
    step_index: stepIndex,
    prev_receipt_hash: prevReceiptHash,
    intended_action: {
      tool_id: toolId,
      audience,
      method,
      canonical_request_hash: canonicalRequestHash,
      typed_args_digest: typedArgsDigest,
      typed_inputs: typedInputs
    },
    capability_token: capabilityToken
  };
}

export function createToolExecutionReceiptObject({
  intentGrantRef = null,
  toolAttestationRef = null,
  requestReceivedAt,
  requestCanonicalHash,
  response,
  idempotencyKey = null,
  toolKeyId = null
}) {
  return {
    domain: PROTOCOL_DOMAINS.TOOL_EXECUTION,
    intent_grant_ref: intentGrantRef,
    tool_attestation_ref: toolAttestationRef,
    request_received_at: requestReceivedAt,
    request_canonical_hash: requestCanonicalHash,
    response,
    idempotency_key: idempotencyKey,
    tool_key_id: toolKeyId
  };
}

export function createObservationReceiptObject({
  sessionId,
  stepIndex,
  intentGrantRef = null,
  toolExecutionReceiptRef = null,
  observedDigest,
  observedAt = null
}) {
  return {
    domain: PROTOCOL_DOMAINS.OBSERVATION,
    session_id: sessionId,
    step_index: stepIndex,
    intent_grant_ref: intentGrantRef,
    tool_execution_receipt_ref: toolExecutionReceiptRef,
    observed_digest: observedDigest,
    observed_at: observedAt
  };
}

export function createAbortReceiptObject({
  sessionId,
  stepIndex,
  prevReceiptHash,
  actionType,
  requestDigest,
  abortReason,
  partialObservationCommitment = null,
  emitTime,
  intentGrantRef = null,
  tokenDigest = null,
  executionStatus = null,
  streamCommitment = null
}) {
  return {
    domain: PROTOCOL_DOMAINS.ABORT,
    session_id: sessionId,
    step_index: stepIndex,
    prev_receipt_hash: prevReceiptHash,
    action_type: actionType,
    request_digest: requestDigest,
    abort_reason: abortReason,
    partial_observation_commitment: partialObservationCommitment,
    emit_time: emitTime,
    intent_grant_ref: intentGrantRef,
    token_digest: tokenDigest,
    execution_status: executionStatus,
    stream_commitment: streamCommitment
  };
}

export function createSessionEndObject({
  sessionId,
  finalCheckpointRef = null,
  prevReceiptHash,
  endReason,
  endTime
}) {
  return {
    domain: PROTOCOL_DOMAINS.SESSION_END,
    session_id: sessionId,
    final_checkpoint_ref: finalCheckpointRef,
    prev_receipt_hash: prevReceiptHash,
    end_reason: endReason,
    end_time: endTime
  };
}

export function validateProtocolObject(object, domain, requiredFields = []) {
  const errors = [];

  if (!object || typeof object !== "object") {
    return { ok: false, errors: ["protocol object must be an object"] };
  }

  if (object.domain !== domain) {
    errors.push(`domain must be ${domain}`);
  }

  for (const field of requiredFields) {
    if (object[field] === undefined || object[field] === null) {
      errors.push(`${field} is required`);
    }
  }

  return { ok: errors.length === 0, errors };
}

export function validateSessionStartObject(object) {
  return validateProtocolObject(object, PROTOCOL_DOMAINS.SESSION_START, [
    "session_id",
    "governance_policy_hash",
    "start_time"
  ]);
}

export function validateIntentGrantObject(object) {
  const result = validateProtocolObject(object, PROTOCOL_DOMAINS.INTENT_GRANT, [
    "session_id",
    "step_index",
    "prev_receipt_hash",
    "intended_action",
    "capability_token"
  ]);
  const errors = [...result.errors];

  if (!object?.intended_action?.canonical_request_hash) {
    errors.push("intended_action.canonical_request_hash is required");
  }

  if (!object?.capability_token?.token_id) {
    errors.push("capability_token.token_id is required");
  }

  return { ok: errors.length === 0, errors };
}

export function validateObservationReceiptObject(object) {
  return validateProtocolObject(object, PROTOCOL_DOMAINS.OBSERVATION, [
    "session_id",
    "step_index",
    "observed_digest"
  ]);
}

export function validateAbortReceiptObject(object) {
  return validateProtocolObject(object, PROTOCOL_DOMAINS.ABORT, [
    "session_id",
    "step_index",
    "prev_receipt_hash",
    "action_type",
    "request_digest",
    "abort_reason",
    "emit_time"
  ]);
}

export function validateSessionEndObject(object) {
  return validateProtocolObject(object, PROTOCOL_DOMAINS.SESSION_END, [
    "session_id",
    "prev_receipt_hash",
    "end_reason",
    "end_time"
  ]);
}

import { randomUUID } from "node:crypto";
import { admissionManifestDigest, verifierProfileDigest } from "./admission.js";
import { mintCapability, capabilityDigest } from "./capability.js";
import { createCheckpointStatement, signCheckpoint } from "./checkpoint.js";
import { sessionReferenceDigest } from "./cross-session.js";
import { createStreamCommitment } from "./stream.js";
import {
  createStampedOutput,
  signStampedOutput,
  stampedOutputDigest,
  stampedOutputPayload
} from "./stamped-output.js";
import {
  dataQueryDigest,
  digestValue,
  humanApprovalDigest,
  modelRequestDigest,
  toolRequestDigest
} from "./digests.js";
import { dissentNoticeDigest } from "./dissent.js";
import { createQuorumCertificateAsync, quorumSubjectDigest } from "./quorum.js";
import { GENESIS_ROOT, signReceipt } from "./receipt.js";
import {
  createAbortReceiptObject,
  createActionReceiptObject,
  createIntentGrantObject,
  createObservationReceiptObject,
  createSessionEndObject,
  createSessionStartObject
} from "./schemas/v0_3.js";

export class ActionGateway {
  constructor({
    log,
    signer,
    tools = {},
    policyHash,
    verifierProfileHash,
    admissionManifestHash,
    verifierProfile = null,
    admissionManifest = null,
    witnesses = [],
    sideEffectWitnessThreshold = witnesses.length === 0 ? 0 : Math.min(2, witnesses.length),
    sessionBoundaryWitnessThreshold = witnesses.length === 0 ? 0 : Math.min(2, witnesses.length),
    checkpointWitnessThreshold = witnesses.length === 0 ? 0 : Math.min(2, witnesses.length),
    outputStampWitnessThreshold = witnesses.length === 0 ? 0 : Math.min(2, witnesses.length),
    transparencyLog = null,
    clock = () => new Date()
  }) {
    this.log = log;
    this.signer = signer;
    this.tools = tools;
    this.policyHash = policyHash;
    this.verifierProfile = verifierProfile;
    this.admissionManifest = admissionManifest;
    this.verifierProfileHash = verifierProfileHash ?? (verifierProfile ? verifierProfileDigest(verifierProfile) : null);
    this.admissionManifestHash = admissionManifestHash ?? (admissionManifest ? admissionManifestDigest(admissionManifest) : null);
    this.witnesses = witnesses;
    this.sideEffectWitnessThreshold = sideEffectWitnessThreshold;
    this.sessionBoundaryWitnessThreshold = sessionBoundaryWitnessThreshold;
    this.checkpointWitnessThreshold = checkpointWitnessThreshold;
    this.outputStampWitnessThreshold = outputStampWitnessThreshold;
    this.transparencyLog = transparencyLog;
    this.clock = clock;
    this.receipts = log.readAll();
    this.sessionId = this.receipts[0]?.session_id ?? null;
    this.stepIndex = this.receipts.reduce((max, receipt) => Math.max(max, receipt.step_index), -1);
    this.lastStateRoot = this.receipts.at(-1)?.state_root ?? GENESIS_ROOT;
  }

  async startSession({ sessionId = `sess_${randomUUID()}`, taskInputDigest = null, crossSessionReferences = [] } = {}) {
    if (this.sessionId) {
      throw new Error(`Session already started: ${this.sessionId}`);
    }

    this.sessionId = sessionId;
    this.stepIndex = 0;
    const issuedAt = this.clock().toISOString();
    const sessionStartSubject = createSessionStartObject({
      sessionId,
      governanceId: this.admissionManifest?.governance_id ?? null,
      governancePolicyHash: this.policyHash,
      witnessSetId: this.admissionManifest?.witness_set_id ?? null,
      witnessSetEpoch: 0,
      agentAttestationRef: this.admissionManifest?.agent_evidence?.attestation_ref ?? null,
      gatewayAttestationRef: this.admissionManifest?.gateway_evidence?.attestation_ref ?? null,
      verifierAttestationRef: this.admissionManifest?.verifier_evidence?.attestation_ref ?? null,
      admissionManifestHash: this.admissionManifestHash,
      verifierProfileHash: this.verifierProfileHash,
      crossSessionReferenceDigests: crossSessionReferences.map(sessionReferenceDigest),
      startTime: issuedAt,
      initialInputsCommitment: taskInputDigest
    });

    return this.appendGatewayReceipt("session.start", {
      session_start_subject: sessionStartSubject,
      quorum_certificate: await this.collectQuorum(sessionStartSubject, this.sessionBoundaryWitnessThreshold),
      transparency_log_inclusion: await this.appendTransparency(sessionStartSubject),
      task_input_digest: taskInputDigest,
      cross_session_references: crossSessionReferences,
      policy_hash: this.policyHash,
      verifier_profile_hash: this.verifierProfileHash,
      admission_manifest_hash: this.admissionManifestHash,
      verifier_profile: this.verifierProfile,
      admission_manifest: this.admissionManifest
    }, { stepIndex: 0 });
  }

  async endSession(reason = "complete") {
    this.ensureSession();
    const stepIndex = this.stepIndex + 1;
    const issuedAt = this.clock().toISOString();
    const sessionEndSubject = createSessionEndObject({
      sessionId: this.sessionId,
      finalCheckpointRef: null,
      prevReceiptHash: this.lastStateRoot,
      endReason: reason,
      endTime: issuedAt
    });

    return this.appendGatewayReceipt("session.end", {
      reason,
      session_end_subject: sessionEndSubject,
      quorum_certificate: await this.collectQuorum(sessionEndSubject, this.sessionBoundaryWitnessThreshold),
      transparency_log_inclusion: await this.appendTransparency(sessionEndSubject)
    }, { stepIndex });
  }

  async modelCall({ prompt, model = "mock.local", parameters = {} }) {
    this.ensureSession();
    const stepIndex = this.nextStep();
    const requestDigest = modelRequestDigest({ model, prompt, parameters });

    const requestReceipt = await this.appendGatewayReceipt("model.request", {
      action_type: "model.call",
      model,
      parameters,
      request_digest: requestDigest
    }, { stepIndex });

    const output = {
      model,
      text: `mock response for ${prompt}`,
      request_digest: requestDigest
    };
    const outputDigest = digestValue(output);
    const responseReceipt = await this.appendGatewayReceipt("model.response", {
      request_receipt_root: requestReceipt.state_root,
      output_digest: outputDigest,
      evidence_ref: `worm://local/${this.sessionId}/${stepIndex}/model-response`,
      action_receipt: createActionReceiptObject({
        sessionId: this.sessionId,
        stepIndex,
        prevReceiptHash: requestReceipt.state_root,
        actionType: "model.call",
        actionManifest: { model, parameters, request_digest: requestDigest },
        observation: { response_commitment: outputDigest, error: null },
        gatewayKeyId: this.signer.keyId,
        emittedAt: this.clock().toISOString()
      })
    }, { stepIndex });

    await this.observe(outputDigest, { stepIndex, sourceReceiptRoot: responseReceipt.state_root });
    return { output, receipts: [requestReceipt, responseReceipt] };
  }

  async abortModelCall({ prompt, model = "mock.local", parameters = {}, reason = "aborted", partialOutput = "" }) {
    this.ensureSession();
    const stepIndex = this.nextStep();
    const requestDigest = modelRequestDigest({ model, prompt, parameters });

    const requestReceipt = await this.appendGatewayReceipt("model.request", {
      action_type: "model.call",
      model,
      parameters,
      request_digest: requestDigest
    }, { stepIndex });

    const partialObservationCommitment = partialOutput ? digestValue({ partial_output: partialOutput }) : null;
    const abortSubject = createAbortReceiptObject({
      sessionId: this.sessionId,
      stepIndex,
      prevReceiptHash: requestReceipt.state_root,
      actionType: "model.call",
      requestDigest,
      abortReason: reason,
      partialObservationCommitment,
      emitTime: this.clock().toISOString()
    });

    const abortReceipt = await this.appendGatewayReceipt("abort", {
      abort_subject: abortSubject,
      action_type: "model.call",
      request_receipt_root: requestReceipt.state_root,
      request_digest: requestDigest,
      abort_reason: reason,
      partial_observation_commitment: partialObservationCommitment
    }, { stepIndex });

    return { receipts: [requestReceipt, abortReceipt], abort: abortSubject };
  }

  async abortStreamingModelCall({
    prompt,
    model = "mock.local",
    parameters = {},
    reason = "stream-aborted",
    chunks = [],
    streamId = `stream_${randomUUID()}`
  }) {
    this.ensureSession();
    const stepIndex = this.nextStep();
    const requestDigest = modelRequestDigest({ model, prompt, parameters });

    const requestReceipt = await this.appendGatewayReceipt("model.request", {
      action_type: "model.call",
      model,
      parameters,
      request_digest: requestDigest,
      stream_id: streamId
    }, { stepIndex });

    const streamCommitment = createStreamCommitment({ streamId, chunks });
    const abortSubject = createAbortReceiptObject({
      sessionId: this.sessionId,
      stepIndex,
      prevReceiptHash: requestReceipt.state_root,
      actionType: "model.call",
      requestDigest,
      abortReason: reason,
      partialObservationCommitment: streamCommitment.partial_merkle_root,
      emitTime: this.clock().toISOString(),
      streamCommitment
    });

    const abortReceipt = await this.appendGatewayReceipt("abort", {
      abort_subject: abortSubject,
      action_type: "model.call",
      request_receipt_root: requestReceipt.state_root,
      request_digest: requestDigest,
      abort_reason: reason,
      partial_observation_commitment: streamCommitment.partial_merkle_root,
      stream_commitment: streamCommitment
    }, { stepIndex });

    return { receipts: [requestReceipt, abortReceipt], abort: abortSubject, streamCommitment };
  }

  async dataQuery({ source = "mock-db", query, parameters = {} }) {
    this.ensureSession();
    const stepIndex = this.nextStep();
    const requestDigest = dataQueryDigest({ source, query, parameters });

    const requestReceipt = await this.appendGatewayReceipt("data.request", {
      action_type: "data.query",
      source,
      request_digest: requestDigest
    }, { stepIndex });

    const output = {
      source,
      rows: [{ id: "row_1", value: `mock result for ${query}` }]
    };
    const outputDigest = digestValue(output);
    const responseReceipt = await this.appendGatewayReceipt("data.response", {
      request_receipt_root: requestReceipt.state_root,
      output_digest: outputDigest,
      evidence_ref: `worm://local/${this.sessionId}/${stepIndex}/data-response`,
      action_receipt: createActionReceiptObject({
        sessionId: this.sessionId,
        stepIndex,
        prevReceiptHash: requestReceipt.state_root,
        actionType: "data.query",
        actionManifest: { source, parameters, request_digest: requestDigest },
        observation: { response_commitment: outputDigest, error: null },
        gatewayKeyId: this.signer.keyId,
        emittedAt: this.clock().toISOString()
      })
    }, { stepIndex });

    await this.observe(outputDigest, { stepIndex, sourceReceiptRoot: responseReceipt.state_root });
    return { output, receipts: [requestReceipt, responseReceipt] };
  }

  async humanApproval({ approver = "human:operator", question, context = {}, approved = true }) {
    this.ensureSession();
    const stepIndex = this.nextStep();
    const requestDigest = humanApprovalDigest({ approver, question, context });

    const requestReceipt = await this.appendGatewayReceipt("human.approval.request", {
      action_type: "human.approval",
      approver,
      request_digest: requestDigest
    }, { stepIndex });

    const output = {
      approver,
      approved,
      question,
      context_digest: digestValue(context)
    };
    const outputDigest = digestValue(output);
    const responseReceipt = await this.appendGatewayReceipt("human.approval.response", {
      request_receipt_root: requestReceipt.state_root,
      output_digest: outputDigest,
      evidence_ref: `worm://local/${this.sessionId}/${stepIndex}/human-approval`,
      action_receipt: createActionReceiptObject({
        sessionId: this.sessionId,
        stepIndex,
        prevReceiptHash: requestReceipt.state_root,
        actionType: "human.approval",
        actionManifest: { approver, context_digest: digestValue(context), request_digest: requestDigest },
        observation: { response_commitment: outputDigest, error: null },
        gatewayKeyId: this.signer.keyId,
        emittedAt: this.clock().toISOString()
      })
    }, { stepIndex });

    await this.observe(outputDigest, { stepIndex, sourceReceiptRoot: responseReceipt.state_root });
    return { output, receipts: [requestReceipt, responseReceipt] };
  }

  async toolCall({ toolName, method, request, inputEdges = [] }) {
    this.ensureSession();
    const tool = this.tools[toolName];
    if (!tool) {
      throw new Error(`Unknown tool: ${toolName}`);
    }

    const stepIndex = this.nextStep();
    const requestDigest = toolRequestDigest({
      toolAudience: tool.audience,
      method,
      request
    });

    const requestReceipt = await this.appendGatewayReceipt("tool.request", {
      action_type: "tool.call",
      tool_audience: tool.audience,
      method,
      request_digest: requestDigest
    }, { stepIndex });

    const grantId = `grant_${randomUUID()}`;
    const capability = mintCapability({
      token_id: `cap_${randomUUID()}`,
      grant_id: grantId,
      session_id: this.sessionId,
      step_index: stepIndex,
      actor: "agent:primary",
      tool_audience: tool.audience,
      action_type: "tool.call",
      method,
      request_digest: requestDigest,
      idempotency_key: `idem_${randomUUID()}`,
      nonce: randomUUID(),
      max_uses: 1,
      policy_hash: this.policyHash,
      prev_state_root: requestReceipt.state_root,
      expires_at: new Date(this.clock().getTime() + 5 * 60 * 1000).toISOString()
    }, this.signer);
    const tokenDigest = capabilityDigest(capability);

    const intentSubject = createIntentGrantObject({
      sessionId: this.sessionId,
      stepIndex,
      prevReceiptHash: requestReceipt.state_root,
      toolId: tool.name,
      audience: tool.audience,
      method,
      canonicalRequestHash: requestDigest,
      typedArgsDigest: digestValue(request),
      typedInputs: inputEdges,
      capabilityToken: capability.claims
    });
    const intentQuorum = await this.collectQuorum(intentSubject, this.sideEffectWitnessThreshold);

    const grantReceipt = await this.appendGatewayReceipt("intent.grant", {
      intent_grant_digest: quorumSubjectDigest(intentSubject),
      intent: intentSubject,
      token_digest: tokenDigest,
      capability,
      quorum_certificate: intentQuorum
    }, { stepIndex });

    const execution = await tool.execute({
      token: capability,
      request,
      requestDigest,
      prevStateRoot: grantReceipt.state_root,
      sessionId: this.sessionId,
      stepIndex,
      intentGrantRef: grantReceipt.state_root,
      intentQuorum
    });

    await this.appendExternalReceipt(execution.receipt);
    await this.observe(execution.receipt.body.output_digest, {
      stepIndex,
      sourceReceiptRoot: execution.receipt.state_root,
      intentGrantRef: grantReceipt.state_root,
      witnessed: this.sideEffectWitnessThreshold > 0
    });

    return {
      output: execution.output,
      capability,
      intentQuorum,
      receipts: [requestReceipt, grantReceipt, execution.receipt]
    };
  }

  async abortToolCall({
    toolName,
    method,
    request,
    inputEdges = [],
    reason = "tool_unreachable",
    executionStatus = "tool_unreachable"
  }) {
    this.ensureSession();
    const tool = this.tools[toolName];
    if (!tool) {
      throw new Error(`Unknown tool: ${toolName}`);
    }

    const stepIndex = this.nextStep();
    const requestDigest = toolRequestDigest({
      toolAudience: tool.audience,
      method,
      request
    });

    const requestReceipt = await this.appendGatewayReceipt("tool.request", {
      action_type: "tool.call",
      tool_audience: tool.audience,
      method,
      request_digest: requestDigest
    }, { stepIndex });

    const grantId = `grant_${randomUUID()}`;
    const capability = mintCapability({
      token_id: `cap_${randomUUID()}`,
      grant_id: grantId,
      session_id: this.sessionId,
      step_index: stepIndex,
      actor: "agent:primary",
      tool_audience: tool.audience,
      action_type: "tool.call",
      method,
      request_digest: requestDigest,
      idempotency_key: `idem_${randomUUID()}`,
      nonce: randomUUID(),
      max_uses: 1,
      policy_hash: this.policyHash,
      prev_state_root: requestReceipt.state_root,
      expires_at: new Date(this.clock().getTime() + 5 * 60 * 1000).toISOString()
    }, this.signer);
    const tokenDigest = capabilityDigest(capability);

    const intentSubject = createIntentGrantObject({
      sessionId: this.sessionId,
      stepIndex,
      prevReceiptHash: requestReceipt.state_root,
      toolId: tool.name,
      audience: tool.audience,
      method,
      canonicalRequestHash: requestDigest,
      typedArgsDigest: digestValue(request),
      typedInputs: inputEdges,
      capabilityToken: capability.claims
    });
    const intentQuorum = await this.collectQuorum(intentSubject, this.sideEffectWitnessThreshold);
    const grantReceipt = await this.appendGatewayReceipt("intent.grant", {
      intent_grant_digest: quorumSubjectDigest(intentSubject),
      intent: intentSubject,
      token_digest: tokenDigest,
      capability,
      quorum_certificate: intentQuorum
    }, { stepIndex });

    const abortSubject = createAbortReceiptObject({
      sessionId: this.sessionId,
      stepIndex,
      prevReceiptHash: grantReceipt.state_root,
      actionType: "tool.call",
      requestDigest,
      abortReason: reason,
      partialObservationCommitment: null,
      emitTime: this.clock().toISOString(),
      intentGrantRef: grantReceipt.state_root,
      tokenDigest,
      executionStatus
    });

    const abortReceipt = await this.appendGatewayReceipt("abort", {
      abort_subject: abortSubject,
      action_type: "tool.call",
      request_receipt_root: requestReceipt.state_root,
      intent_grant_ref: grantReceipt.state_root,
      token_digest: tokenDigest,
      request_digest: requestDigest,
      abort_reason: reason,
      partial_observation_commitment: null,
      execution_status: executionStatus
    }, { stepIndex });

    return {
      capability,
      intentQuorum,
      abort: abortSubject,
      receipts: [requestReceipt, grantReceipt, abortReceipt]
    };
  }

  async createCheckpoint({ checkpointId = `chk_${randomUUID()}`, checkpointIndex = 0, prevCheckpointHash = null } = {}) {
    const statement = createCheckpointStatement(this.receipts, {
      checkpointId,
      checkpointIndex,
      prevCheckpointHash,
      sessionId: this.sessionId,
      policyHash: this.policyHash,
      verifierProfileHash: this.verifierProfileHash,
      issuedAt: this.clock().toISOString()
    });
    const checkpoint = signCheckpoint(statement, this.signer);
    checkpoint.quorum_certificate = await this.collectQuorum(statement, this.checkpointWitnessThreshold);
    checkpoint.transparency_log_inclusion = await this.appendTransparency(statement);
    return checkpoint;
  }

  async recordDissentNotice(notice) {
    this.ensureSession();
    if (notice.subject?.session_id !== this.sessionId) {
      throw new Error("Dissent notice session does not match active session");
    }

    return this.appendGatewayReceipt("dissent.notice", {
      notice_digest: dissentNoticeDigest(notice),
      notice,
      target_receipt_hash: notice.subject.target_receipt_hash,
      notice_class: notice.subject.notice_class
    }, { stepIndex: this.stepIndex });
  }

  async stampOutput({
    output,
    sourceReceiptRoot,
    observationReceiptRoot = null,
    outputDigest = null,
    outputSchemaHash = null,
    outputRef = null,
    contentType = "application/json",
    checkpointRef = null,
    receiptLogRef = null,
    certificateRef = null,
    transparencyLogRef = null,
    sinkRef = null,
    includeTransparency = false,
    witnessCosign = false
  }) {
    this.ensureSession();
    const digest = outputDigest ?? digestValue(output);
    const sourceReceipt = this.receipts.find((receipt) => receipt.state_root === sourceReceiptRoot);
    if (!sourceReceipt) {
      throw new Error("Cannot stamp output: source receipt not found");
    }

    const observationReceipt = observationReceiptRoot
      ? this.receipts.find((receipt) => receipt.state_root === observationReceiptRoot)
      : this.receipts.find((receipt) => receipt.kind === "observation" && receipt.body?.source_receipt_root === sourceReceiptRoot);

    if (!observationReceipt) {
      throw new Error("Cannot stamp output: observation receipt not found");
    }

    if (observationReceipt.body?.observed_digest !== digest) {
      throw new Error("Cannot stamp output: observation digest does not match output digest");
    }

    const baseStamp = createStampedOutput({
      stampId: `stamp_${randomUUID()}`,
      sessionId: this.sessionId,
      sourceReceiptRoot,
      observationReceiptRoot: observationReceipt.state_root,
      outputDigest: digest,
      outputSchemaHash,
      outputRef,
      contentType,
      admissionManifestHash: this.admissionManifestHash,
      verifierProfileHash: this.verifierProfileHash,
      agentAttestationRef: this.admissionManifest?.agent_evidence?.attestation_ref ?? null,
      gatewayAttestationRef: this.admissionManifest?.gateway_evidence?.attestation_ref ?? null,
      verifierAttestationRef: this.admissionManifest?.verifier_evidence?.attestation_ref ?? null,
      checkpointRef,
      receiptLogRef,
      certificateRef,
      transparencyLogRef,
      issuedAt: this.clock().toISOString()
    });
    let stamp = signStampedOutput(baseStamp, this.signer);

    if (witnessCosign) {
      stamp = {
        ...stamp,
        quorum_certificate: await this.collectQuorum(stampedOutputPayload(stamp), this.outputStampWitnessThreshold)
      };
    }

    if (includeTransparency) {
      stamp = {
        ...stamp,
        transparency_log_inclusion: await this.appendTransparency(stampedOutputPayload(stamp))
      };
    }

    const stampDigest = stampedOutputDigest(stamp);
    const receipt = await this.appendGatewayReceipt("output.stamped", {
      stamped_output_digest: stampDigest,
      stamped_output: stamp,
      stamp_id: stamp.stamp_id,
      source_receipt_root: sourceReceiptRoot,
      observation_receipt_root: observationReceipt.state_root,
      output_digest: digest,
      sink_ref: sinkRef
    }, { stepIndex: this.stepIndex });

    return { stamp, stampDigest, receipt };
  }

  async observe(observedDigest, { stepIndex, sourceReceiptRoot, intentGrantRef = null, witnessed = false }) {
    const body = {
      observed_digest: observedDigest,
      source_receipt_root: sourceReceiptRoot
    };

    if (intentGrantRef) {
      body.intent_grant_ref = intentGrantRef;
    }

    if (witnessed) {
      const observationSubject = createObservationReceiptObject({
        sessionId: this.sessionId,
        stepIndex,
        intentGrantRef,
        toolExecutionReceiptRef: sourceReceiptRoot,
        observedDigest,
        observedAt: this.clock().toISOString()
      });
      body.observation_subject = observationSubject;
      body.quorum_certificate = await this.collectQuorum(observationSubject, this.sideEffectWitnessThreshold);
    }

    return this.appendGatewayReceipt("observation", body, { stepIndex });
  }

  async collectQuorum(subject, threshold) {
    if (threshold < 1) {
      return null;
    }
    return createQuorumCertificateAsync(subject, this.witnesses, { threshold });
  }

  async appendTransparency(subject) {
    if (!this.transparencyLog) {
      return null;
    }
    return this.transparencyLog.append(subject);
  }

  async appendGatewayReceipt(kind, body, { stepIndex }) {
    const receipt = signReceipt({
      kind,
      session_id: this.sessionId,
      step_index: stepIndex,
      prev_state_root: this.lastStateRoot,
      actor: { type: "gateway", id: "local" },
      body,
      issued_at: this.clock().toISOString()
    }, this.signer);

    return this.appendExternalReceipt(receipt);
  }

  async appendExternalReceipt(receipt) {
    if (receipt.prev_state_root !== this.lastStateRoot) {
      throw new Error("Receipt does not extend the current state root");
    }
    await this.log.append(receipt);
    this.receipts.push(receipt);
    this.lastStateRoot = receipt.state_root;
    this.stepIndex = Math.max(this.stepIndex, receipt.step_index);
    return receipt;
  }

  nextStep() {
    this.stepIndex += 1;
    return this.stepIndex;
  }

  ensureSession() {
    if (!this.sessionId) {
      throw new Error("Session has not started");
    }
  }
}

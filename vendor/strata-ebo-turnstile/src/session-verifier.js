import { capabilityDigest, verifyCapability } from "./capability.js";
import { canonicalize } from "./canonicalize.js";
import { admissionManifestDigest, validateAdmissionManifest, verifierProfileDigest } from "./admission.js";
import { sessionReferenceDigest, verifySessionReferences } from "./cross-session.js";
import { verifyDissentNotice } from "./dissent.js";
import { verifyQuorumCertificate } from "./quorum.js";
import { verifyReceiptChain } from "./receipt.js";
import { verifyStreamCommitment } from "./stream.js";
import { stampedOutputDigest, verifyStampedOutput } from "./stamped-output.js";
import { verifyTransparencyInclusion } from "./transparency-log.js";

const REQUEST_KINDS = new Set([
  "model.request",
  "data.request",
  "tool.request",
  "human.approval.request"
]);

const OUTPUT_KINDS = new Set([
  "model.response",
  "data.response",
  "tool.execution",
  "human.approval.response"
]);

export function verifySession(receipts, keyring, options = {}) {
  const chain = verifyReceiptChain(receipts, keyring, options);
  const errors = [...chain.errors];
  const warnings = [];
  const grantedTokens = new Map();
  const usedTokens = new Set();
  let pendingAction = null;
  let pendingObservation = null;
  const sessionId = receipts[0]?.session_id;

  if (receipts.length > 0 && receipts[0].kind !== "session.start") {
    errors.push("first receipt must be session.start");
  }

  receipts.forEach((receipt, index) => {
    if (sessionId && receipt.session_id !== sessionId) {
      errors.push(`receipt ${index} session_id mismatch`);
    }

    if (REQUEST_KINDS.has(receipt.kind) && pendingObservation) {
      errors.push(`receipt ${index} starts ${receipt.kind} before observing ${pendingObservation}`);
    }

    if (REQUEST_KINDS.has(receipt.kind)) {
      if (pendingAction) {
        errors.push(`receipt ${index} starts ${receipt.kind} before completing ${pendingAction.kind}`);
      }
      pendingAction = {
        kind: receipt.kind,
        step_index: receipt.step_index,
        request_digest: receipt.body?.request_digest,
        state_root: receipt.state_root,
        intent_grant_ref: null,
        token_digest: null
      };
    }

    if (receipt.kind === "session.start") {
      verifySessionStart(receipt, index, options, keyring, errors, warnings);
    }

    if (receipt.kind === "session.end") {
      verifySessionEnd(receipt, index, options, keyring, errors);
    }

    if (receipt.kind === "token.grant" || receipt.kind === "intent.grant") {
      const token = receipt.body?.capability;
      if (!token) {
        errors.push(`receipt ${index} ${receipt.kind} missing capability`);
        return;
      }

      if (receipt.kind === "intent.grant") {
        if (!receipt.body.intent) {
          errors.push(`receipt ${index} intent.grant missing intent subject`);
        } else if (receipt.body.quorum_certificate) {
          const quorum = verifyQuorumCertificate(receipt.body.intent, receipt.body.quorum_certificate, keyring);
          errors.push(...quorum.errors.map((error) => `receipt ${index} intent quorum: ${error}`));
          collectTaintWarnings(receipt.body.intent.intended_action?.typed_inputs, index, warnings);
        } else if (options.requireSideEffectQuorum) {
          errors.push(`receipt ${index} intent.grant missing quorum certificate`);
        }
        if (pendingAction) {
          pendingAction.intent_grant_ref = receipt.state_root;
          pendingAction.token_digest = receipt.body?.token_digest;
        }
      }

      const digest = capabilityDigest(token);
      if (receipt.body.token_digest && receipt.body.token_digest !== digest) {
        errors.push(`receipt ${index} token_digest does not match capability`);
      }

      const result = verifyCapability(token, keyring, {
        now: options.now ?? receipt.issued_at
      });
      errors.push(...result.errors.map((error) => `receipt ${index} capability: ${error}`));

      const previousReceipt = receipts[index - 1];
      if (previousReceipt?.kind !== "tool.request") {
        errors.push(`receipt ${index} ${receipt.kind} is not preceded by tool.request`);
      } else {
        if (previousReceipt.body?.tool_audience !== token.claims.tool_audience) {
          errors.push(`receipt ${index} capability audience does not match preceding tool.request`);
        }
        if (previousReceipt.body?.method !== token.claims.method) {
          errors.push(`receipt ${index} capability method does not match preceding tool.request`);
        }
        if (previousReceipt.body?.request_digest !== token.claims.request_digest) {
          errors.push(`receipt ${index} capability request digest does not match preceding tool.request`);
        }
      }

      if (token.claims.session_id !== receipt.session_id) {
        errors.push(`receipt ${index} capability session_id mismatch`);
      }

      if (token.claims.step_index !== receipt.step_index) {
        errors.push(`receipt ${index} capability step_index mismatch`);
      }

      if (token.claims.prev_state_root !== receipt.prev_state_root) {
        errors.push(`receipt ${index} capability previous state root does not match grant predecessor`);
      }

      grantedTokens.set(digest, token);
    }

    if (receipt.kind === "tool.execution") {
      const tokenDigest = receipt.body?.token_digest;
      const token = grantedTokens.get(tokenDigest);

      if (!token) {
        errors.push(`receipt ${index} tool.execution references unknown token`);
      } else {
        if (usedTokens.has(tokenDigest)) {
          errors.push(`receipt ${index} capability token was already used`);
        }
        usedTokens.add(tokenDigest);

        const result = verifyCapability(token, keyring, {
          audience: receipt.actor?.id,
          method: receipt.body?.method,
          requestDigest: receipt.body?.request_digest,
          now: options.now ?? receipt.issued_at
        });
        errors.push(...result.errors.map((error) => `receipt ${index} capability: ${error}`));
      }

      if (receipt.body?.certification?.tool_verified_capability === false) {
        warnings.push(`receipt ${index} tool execution is tainted as uncertified_tool`);
      }
    }

    if (OUTPUT_KINDS.has(receipt.kind)) {
      pendingAction = null;
      pendingObservation = receipt.body?.output_digest ?? receipt.body?.response_digest ?? null;
    }

    if (receipt.kind === "abort") {
      verifyAbortReceipt(receipt, index, pendingAction, errors);
      pendingAction = null;
    }

    if (receipt.kind === "dissent.notice") {
      const result = verifyDissentNotice(receipt.body?.notice, receipts, keyring, {
        failOnPolicyDissent: options.failOnPolicyDissent
      });
      errors.push(...result.errors.map((error) => `receipt ${index} dissent: ${error}`));
      warnings.push(...result.warnings.map((warning) => `receipt ${index} dissent: ${warning}`));
    }

    if (receipt.kind === "output.stamped") {
      verifyOutputStampedReceipt(receipt, index, receipts, keyring, options, errors);
    }

    if (receipt.kind === "observation") {
      const observed = receipt.body?.observed_digest;
      if (!pendingObservation) {
        errors.push(`receipt ${index} observation has no pending output`);
      } else if (observed !== pendingObservation) {
        errors.push(`receipt ${index} observation digest mismatch`);
      } else {
        pendingObservation = null;
      }

      if (receipt.body?.intent_grant_ref || receipt.body?.quorum_certificate) {
        if (!receipt.body.observation_subject && (receipt.body.quorum_certificate || options.requireSideEffectQuorum)) {
          errors.push(`receipt ${index} witnessed observation missing observation_subject`);
        } else if (receipt.body.quorum_certificate) {
          const quorum = verifyQuorumCertificate(receipt.body.observation_subject, receipt.body.quorum_certificate, keyring);
          errors.push(...quorum.errors.map((error) => `receipt ${index} observation quorum: ${error}`));
          if (receipt.body.observation_subject.observed_digest !== receipt.body.observed_digest) {
            errors.push(`receipt ${index} observation subject digest mismatch`);
          }
          if (receipt.body.observation_subject.tool_execution_receipt_ref !== receipt.body.source_receipt_root) {
            errors.push(`receipt ${index} observation subject source mismatch`);
          }
        } else if (options.requireSideEffectQuorum) {
          errors.push(`receipt ${index} witnessed observation missing quorum certificate`);
        }
      }
    }
  });

  if (pendingObservation) {
    errors.push(`session ended with unobserved output ${pendingObservation}`);
  }

  if (pendingAction) {
    errors.push(`session ended with incomplete action ${pendingAction.kind}`);
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    finalStateRoot: chain.finalStateRoot
  };
}

function verifyOutputStampedReceipt(receipt, index, receipts, keyring, options, errors) {
  const stamp = receipt.body?.stamped_output;

  if (!stamp) {
    errors.push(`receipt ${index} output.stamped missing stamped_output`);
    return;
  }

  const digest = stampedOutputDigest(stamp);
  if (receipt.body.stamped_output_digest !== digest) {
    errors.push(`receipt ${index} output.stamped digest mismatch`);
  }

  if (receipt.body.stamp_id !== stamp.stamp_id) {
    errors.push(`receipt ${index} output.stamped stamp_id mismatch`);
  }

  if (receipt.body.source_receipt_root !== stamp.source_receipt_root) {
    errors.push(`receipt ${index} output.stamped source receipt mismatch`);
  }

  if (receipt.body.observation_receipt_root !== stamp.observation_receipt_root) {
    errors.push(`receipt ${index} output.stamped observation receipt mismatch`);
  }

  if (receipt.body.output_digest !== stamp.output_digest) {
    errors.push(`receipt ${index} output.stamped output digest mismatch`);
  }

  const result = verifyStampedOutput(stamp, {
    receipts,
    keyring,
    transparencyLogEntries: options.transparencyLogEntries,
    requireTransparencyLog: options.requireStampedOutputTransparency,
    requireQuorum: options.requireStampedOutputQuorum
  });
  errors.push(...result.errors.map((error) => `receipt ${index} stamped output: ${error}`));
}

function verifyAbortReceipt(receipt, index, pendingAction, errors) {
  const subject = receipt.body?.abort_subject;

  if (!subject) {
    errors.push(`receipt ${index} abort missing abort_subject`);
    return;
  }

  if (!pendingAction) {
    errors.push(`receipt ${index} abort has no pending action`);
  }

  if (subject.domain !== "turnstile.abort.v1") {
    errors.push(`receipt ${index} abort subject domain mismatch`);
  }

  if (subject.session_id !== receipt.session_id) {
    errors.push(`receipt ${index} abort subject session_id mismatch`);
  }

  if (subject.step_index !== receipt.step_index) {
    errors.push(`receipt ${index} abort subject step_index mismatch`);
  }

  if (subject.prev_receipt_hash !== receipt.prev_state_root) {
    errors.push(`receipt ${index} abort subject previous receipt mismatch`);
  }

  const expectedPrevious = pendingAction?.intent_grant_ref ?? pendingAction?.state_root;
  if (pendingAction && subject.prev_receipt_hash !== expectedPrevious) {
    errors.push(`receipt ${index} abort does not close the pending action`);
  }

  if (pendingAction?.request_digest && subject.request_digest !== pendingAction.request_digest) {
    errors.push(`receipt ${index} abort subject request digest mismatch`);
  }

  if (subject.abort_reason !== receipt.body?.abort_reason) {
    errors.push(`receipt ${index} abort reason mismatch`);
  }

  if (subject.partial_observation_commitment !== receipt.body?.partial_observation_commitment) {
    errors.push(`receipt ${index} abort partial observation mismatch`);
  }

  if (subject.stream_commitment || receipt.body?.stream_commitment) {
    if (!subject.stream_commitment || !receipt.body?.stream_commitment) {
      errors.push(`receipt ${index} abort stream commitment missing from subject or body`);
    } else if (canonicalize(subject.stream_commitment) !== canonicalize(receipt.body.stream_commitment)) {
      errors.push(`receipt ${index} abort stream commitment mismatch`);
    } else {
      const stream = verifyStreamCommitment(subject.stream_commitment);
      errors.push(...stream.errors.map((error) => `receipt ${index} abort stream: ${error}`));
      if (subject.partial_observation_commitment !== subject.stream_commitment.partial_merkle_root) {
        errors.push(`receipt ${index} abort partial observation is not stream partial Merkle root`);
      }
    }
  }

  if (subject.action_type === "tool.call") {
    if (!subject.intent_grant_ref || subject.intent_grant_ref !== receipt.body?.intent_grant_ref) {
      errors.push(`receipt ${index} abort intent grant reference mismatch`);
    }
    if (subject.intent_grant_ref !== pendingAction?.intent_grant_ref) {
      errors.push(`receipt ${index} abort does not reference the pending intent grant`);
    }
    if (!subject.token_digest || subject.token_digest !== receipt.body?.token_digest) {
      errors.push(`receipt ${index} abort token digest mismatch`);
    }
    if (subject.token_digest !== pendingAction?.token_digest) {
      errors.push(`receipt ${index} abort does not reference the pending capability token`);
    }
    if (!isValidToolAbortStatus(subject.execution_status)) {
      errors.push(`receipt ${index} abort execution_status is invalid`);
    }
    if (subject.execution_status !== receipt.body?.execution_status) {
      errors.push(`receipt ${index} abort execution_status mismatch`);
    }
  }
}

function isValidToolAbortStatus(status) {
  return ["not_attempted", "tool_unreachable", "tool_refused", "timeout_unknown"].includes(status);
}

function collectTaintWarnings(inputEdges, index, warnings) {
  for (const edge of inputEdges ?? []) {
    if (edge.taint_label) {
      warnings.push(`receipt ${index} input edge is tainted as ${edge.taint_label}`);
    }
  }
}

function verifySessionStart(receipt, index, options, keyring, errors, warnings) {
  const profile = receipt.body?.verifier_profile;
  const manifest = receipt.body?.admission_manifest;
  const subject = receipt.body?.session_start_subject;
  const crossSessionReferences = receipt.body?.cross_session_references ?? [];

  if (!subject && options.requireBoundaryQuorum) {
    errors.push(`receipt ${index} missing session_start_subject`);
  }

  if (subject) {
    if (subject.session_id !== receipt.session_id) {
      errors.push(`receipt ${index} session_start subject session_id mismatch`);
    }
    if (subject.governance_policy_hash !== receipt.body?.policy_hash) {
      errors.push(`receipt ${index} session_start subject policy hash mismatch`);
    }
    if (subject.admission_manifest_hash !== receipt.body?.admission_manifest_hash) {
      errors.push(`receipt ${index} session_start subject admission hash mismatch`);
    }
    const expectedReferenceDigests = crossSessionReferences.map(sessionReferenceDigest);
    if (JSON.stringify(subject.cross_session_reference_digests ?? []) !== JSON.stringify(expectedReferenceDigests)) {
      errors.push(`receipt ${index} session_start cross-session reference digest mismatch`);
    }
    verifyBoundaryEvidence("session_start", subject, receipt, index, options, keyring, errors);
  }

  const referenceResult = verifySessionReferences(crossSessionReferences, options.priorSessionSummaries, {
    requirePriorSessionSummaries: options.requireCrossSessionSummaries
  });
  errors.push(...referenceResult.errors.map((error) => `receipt ${index} ${error}`));
  warnings.push(...referenceResult.warnings.map((warning) => `receipt ${index} ${warning}`));

  if (profile) {
    const digest = verifierProfileDigest(profile);
    if (receipt.body.verifier_profile_hash && receipt.body.verifier_profile_hash !== digest) {
      errors.push(`receipt ${index} verifier_profile_hash mismatch`);
    }
  } else if (options.requireAdmissionManifest) {
    errors.push(`receipt ${index} missing verifier_profile`);
  }

  if (manifest) {
    const digest = admissionManifestDigest(manifest);
    if (receipt.body.admission_manifest_hash && receipt.body.admission_manifest_hash !== digest) {
      errors.push(`receipt ${index} admission_manifest_hash mismatch`);
    }

    if (profile || options.requireAdmissionManifest) {
      const admission = validateAdmissionManifest(manifest, profile);
      errors.push(...admission.errors.map((error) => `receipt ${index} admission: ${error}`));
    }
  } else if (options.requireAdmissionManifest) {
    errors.push(`receipt ${index} missing admission_manifest`);
  }
}

function verifySessionEnd(receipt, index, options, keyring, errors) {
  const subject = receipt.body?.session_end_subject;

  if (!subject && options.requireBoundaryQuorum) {
    errors.push(`receipt ${index} missing session_end_subject`);
    return;
  }

  if (!subject) {
    return;
  }

  if (subject.session_id !== receipt.session_id) {
    errors.push(`receipt ${index} session_end subject session_id mismatch`);
  }

  if (subject.prev_receipt_hash !== receipt.prev_state_root) {
    errors.push(`receipt ${index} session_end subject previous receipt mismatch`);
  }

  if (subject.end_reason !== receipt.body?.reason) {
    errors.push(`receipt ${index} session_end subject reason mismatch`);
  }

  verifyBoundaryEvidence("session_end", subject, receipt, index, options, keyring, errors);
}

function verifyBoundaryEvidence(label, subject, receipt, index, options, keyring, errors) {
  if (receipt.body?.quorum_certificate) {
    const quorum = verifyQuorumCertificate(subject, receipt.body.quorum_certificate, keyring);
    errors.push(...quorum.errors.map((error) => `receipt ${index} ${label} quorum: ${error}`));
  } else if (options.requireBoundaryQuorum) {
    errors.push(`receipt ${index} ${label} missing quorum certificate`);
  }

  if (receipt.body?.transparency_log_inclusion) {
    const transparency = verifyTransparencyInclusion(
      subject,
      receipt.body.transparency_log_inclusion,
      options.transparencyLogEntries,
      keyring
    );
    errors.push(...transparency.errors.map((error) => `receipt ${index} ${label} transparency: ${error}`));
  } else if (options.requireTransparencyLog) {
    errors.push(`receipt ${index} ${label} missing transparency log inclusion`);
  }
}

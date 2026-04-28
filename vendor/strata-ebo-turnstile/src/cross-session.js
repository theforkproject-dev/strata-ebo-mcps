import { canonicalize } from "./canonicalize.js";
import { sha256Hex } from "./crypto.js";

export const SESSION_SUMMARY_VERSION = "turnstile.session-summary.v1";
export const SESSION_REFERENCE_VERSION = "turnstile.session-reference.v1";

export function createSessionSummary({ receipts, verification, checkpoint = null }) {
  const sessionStart = receipts[0];
  const sessionEnd = receipts.at(-1);
  const warnings = verification?.warnings ?? [];
  const errors = verification?.errors ?? [];

  return {
    version: SESSION_SUMMARY_VERSION,
    session_id: sessionStart?.session_id ?? null,
    final_state_root: verification?.finalStateRoot ?? sessionEnd?.state_root ?? null,
    verifier_profile_hash: sessionStart?.body?.verifier_profile_hash ?? null,
    admission_manifest_hash: sessionStart?.body?.admission_manifest_hash ?? null,
    certificate_digest: sessionCertificateDigest({ receipts, checkpoint }),
    strict_ok: verification?.ok === true,
    warning_count: warnings.length,
    error_count: errors.length,
    dissent_status: classifyDissentStatus({ warnings, errors }),
    warning_digest: sha256Hex(canonicalize(warnings)),
    checkpoint_digest: checkpoint ? sha256Hex(canonicalize(checkpoint)) : null
  };
}

export function createSessionReference({
  referenceId,
  summary,
  dependencyType,
  importedReceiptHash = null,
  importedOutputDigest = null,
  purpose = null
}) {
  return {
    version: SESSION_REFERENCE_VERSION,
    reference_id: referenceId,
    dependency_type: dependencyType,
    source_session_id: summary.session_id,
    source_final_state_root: summary.final_state_root,
    source_certificate_digest: summary.certificate_digest,
    source_verifier_profile_hash: summary.verifier_profile_hash,
    source_admission_manifest_hash: summary.admission_manifest_hash,
    source_strict_ok: summary.strict_ok,
    source_warning_count: summary.warning_count,
    source_dissent_status: summary.dissent_status,
    source_warning_digest: summary.warning_digest,
    imported_receipt_hash: importedReceiptHash,
    imported_output_digest: importedOutputDigest,
    purpose
  };
}

export function sessionReferenceDigest(reference) {
  return sha256Hex(canonicalize(reference));
}

export function verifySessionReferences(references, priorSessionSummaries = [], options = {}) {
  const errors = [];
  const warnings = [];
  const summaries = normalizeSummaries(priorSessionSummaries);

  for (const [index, reference] of (references ?? []).entries()) {
    if (reference.version !== SESSION_REFERENCE_VERSION) {
      errors.push(`cross-session reference ${index} has invalid version`);
      continue;
    }

    const summary = summaries.get(reference.source_session_id) ?? summaries.get(reference.source_final_state_root);
    if (!summary) {
      const message = `cross-session reference ${reference.reference_id} missing prior session summary`;
      if (options.requirePriorSessionSummaries) {
        errors.push(message);
      } else {
        warnings.push(message);
      }
      continue;
    }

    compareReferenceToSummary(reference, summary, errors);

    if (reference.source_strict_ok !== true || summary.strict_ok !== true) {
      errors.push(`cross-session reference ${reference.reference_id} depends on non-strict prior session`);
    }

    if (reference.source_warning_count > 0 || summary.warning_count > 0) {
      warnings.push(`cross-session reference ${reference.reference_id} carries ${summary.warning_count} prior warning(s)`);
    }

    if (reference.source_dissent_status !== "none" || summary.dissent_status !== "none") {
      warnings.push(`cross-session reference ${reference.reference_id} carries prior dissent status: ${summary.dissent_status}`);
    }
  }

  return { ok: errors.length === 0, errors, warnings };
}

function compareReferenceToSummary(reference, summary, errors) {
  const checks = [
    ["source_session_id", "session_id"],
    ["source_final_state_root", "final_state_root"],
    ["source_certificate_digest", "certificate_digest"],
    ["source_verifier_profile_hash", "verifier_profile_hash"],
    ["source_admission_manifest_hash", "admission_manifest_hash"],
    ["source_warning_count", "warning_count"],
    ["source_dissent_status", "dissent_status"],
    ["source_warning_digest", "warning_digest"]
  ];

  for (const [referenceField, summaryField] of checks) {
    if (reference[referenceField] !== summary[summaryField]) {
      errors.push(`cross-session reference ${reference.reference_id} ${referenceField} mismatch`);
    }
  }
}

function normalizeSummaries(priorSessionSummaries) {
  const summaries = new Map();
  const items = priorSessionSummaries?.version === SESSION_SUMMARY_VERSION
    ? [priorSessionSummaries]
    : Array.isArray(priorSessionSummaries)
    ? priorSessionSummaries
    : Object.values(priorSessionSummaries ?? {});

  for (const summary of items) {
    summaries.set(summary.session_id, summary);
    summaries.set(summary.final_state_root, summary);
  }

  return summaries;
}

function sessionCertificateDigest({ receipts, checkpoint }) {
  return sha256Hex(canonicalize({
    protocol: "turnstile-session-certificate-digest-v1",
    receipt_roots: receipts.map((receipt) => receipt.state_root),
    checkpoint_digest: checkpoint ? sha256Hex(canonicalize(checkpoint)) : null
  }));
}

function classifyDissentStatus({ warnings, errors }) {
  if (errors.some((error) => /dissent/.test(error))) {
    return "disputed";
  }

  if (warnings.some((warning) => /dissent/.test(warning))) {
    return "warning";
  }

  return "none";
}

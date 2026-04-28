import { canonicalize } from "./canonicalize.js";
import { sha256Hex } from "./crypto.js";

export const VERIFIER_PROFILE_VERSION = "turnstile.verifier-profile.v1";
export const ADMISSION_MANIFEST_VERSION = "turnstile.admission-manifest.v1";

export function createVerifierProfile(overrides = {}) {
  return {
    version: VERIFIER_PROFILE_VERSION,
    profile_id: overrides.profile_id ?? "profile.local.regulated-workflow.v1",
    accepted_receipt_version: overrides.accepted_receipt_version ?? "turnstile.receipt.v1",
    canonicalization: overrides.canonicalization ?? "turnstile.canonical-json.v1",
    hash_alg: overrides.hash_alg ?? "SHA-256",
    signature_algs: overrides.signature_algs ?? ["Ed25519"],
    requires_tinfoil_attestation: overrides.requires_tinfoil_attestation ?? true,
    requires_debug_mode_false: overrides.requires_debug_mode_false ?? true,
    requires_pinned_image_digest: overrides.requires_pinned_image_digest ?? true,
    requires_config_hash: overrides.requires_config_hash ?? true,
    requires_egress_policy_evidence: overrides.requires_egress_policy_evidence ?? true,
    side_effect_quorum_threshold: overrides.side_effect_quorum_threshold ?? 2,
    checkpoint_quorum_threshold: overrides.checkpoint_quorum_threshold ?? 2,
    allowed_taint_labels: overrides.allowed_taint_labels ?? ["uncertified_input", "uncertified_tool"],
    clock_skew_seconds: overrides.clock_skew_seconds ?? 300
  };
}

export function createTinfoilEvidence({
  containerName,
  imageDigest,
  configHash,
  attestationRef,
  sigstoreBundleRef,
  debugMode = false,
  shimPaths = [],
  egressPolicy = null,
  notes = []
}) {
  return {
    platform: "tinfoil-containers",
    container_name: containerName,
    image_digest: imageDigest,
    tinfoil_config_hash: configHash,
    attestation_ref: attestationRef,
    sigstore_bundle_ref: sigstoreBundleRef,
    debug_mode: debugMode,
    shim_paths: shimPaths,
    egress_policy: egressPolicy,
    notes
  };
}

export function createAdmissionManifest({
  manifestId = "adm_local_demo",
  governanceId = "gov_local_demo",
  agent,
  gateway,
  verifier,
  approvedTools = [],
  approvedDataSources = [],
  approvedModels = [],
  resourceLimits = {},
  witnessSetId = "witness-set.local",
  witnessThreshold = 2,
  policyHash,
  issuedAt = new Date().toISOString()
}) {
  return {
    version: ADMISSION_MANIFEST_VERSION,
    manifest_id: manifestId,
    governance_id: governanceId,
    policy_hash: policyHash,
    issued_at: issuedAt,
    verifier_evidence: verifier,
    agent_evidence: agent,
    gateway_evidence: gateway,
    approved_tools: approvedTools,
    approved_data_sources: approvedDataSources,
    approved_models: approvedModels,
    resource_limits: resourceLimits,
    witness_set_id: witnessSetId,
    witness_threshold: witnessThreshold
  };
}

export function verifierProfileDigest(profile) {
  return sha256Hex(canonicalize(profile));
}

export function admissionManifestDigest(manifest) {
  return sha256Hex(canonicalize(manifest));
}

export function validateAdmissionManifest(manifest, profile = createVerifierProfile()) {
  const errors = [];

  if (!manifest || manifest.version !== ADMISSION_MANIFEST_VERSION) {
    return { ok: false, errors: ["invalid admission manifest version"] };
  }

  const evidenceItems = [
    ["agent", manifest.agent_evidence],
    ["gateway", manifest.gateway_evidence],
    ["verifier", manifest.verifier_evidence]
  ];

  for (const [name, evidence] of evidenceItems) {
    if (!evidence) {
      errors.push(`${name} evidence missing`);
      continue;
    }

    if (profile.requires_tinfoil_attestation && evidence.platform !== "tinfoil-containers") {
      errors.push(`${name} evidence is not Tinfoil Containers evidence`);
    }

    if (profile.requires_pinned_image_digest && !isSha256Digest(evidence.image_digest)) {
      errors.push(`${name} image digest must be pinned with sha256`);
    }

    if (profile.requires_config_hash && !evidence.tinfoil_config_hash) {
      errors.push(`${name} tinfoil_config_hash missing`);
    }

    if (!evidence.attestation_ref) {
      errors.push(`${name} attestation_ref missing`);
    }

    if (!evidence.sigstore_bundle_ref) {
      errors.push(`${name} sigstore_bundle_ref missing`);
    }

    if (profile.requires_debug_mode_false && evidence.debug_mode !== false) {
      errors.push(`${name} debug mode is not allowed by verifier profile`);
    }
  }

  if (profile.requires_egress_policy_evidence && !manifest.gateway_evidence?.egress_policy) {
    errors.push("gateway egress_policy evidence missing");
  }

  if (!Array.isArray(manifest.approved_tools)) {
    errors.push("approved_tools must be an array");
  }

  if (!Number.isInteger(manifest.witness_threshold) || manifest.witness_threshold < 1) {
    errors.push("witness_threshold must be a positive integer");
  }

  return { ok: errors.length === 0, errors };
}

function isSha256Digest(value) {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
}

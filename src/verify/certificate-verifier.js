import {
  digestValue,
  verifyCheckpoint,
  verifyEd25519,
  verifySession,
  verifyWitnessAuthority,
  verifyWitnessRegistryEpoch,
  witnessRegistryEpochDigest
} from "../strata/primitives.js";
import { policyBundleDigest, verifyPolicyQuorumAuthority } from "../policy/email-policy.js";
import { SUPABASE_POLICY_BUNDLE_VERSION, SUPABASE_POLICY_QUORUM_VERSION, supabasePolicyBundleDigest } from "../policy/supabase-policy.js";
import { KOJIMEM_POLICY_BUNDLE_VERSION, KOJIMEM_POLICY_QUORUM_VERSION, kojimemPolicyBundleDigest } from "../policy/kojimem-policy.js";
import {
  SUPABASE_ACTION_CERTIFICATE_VERSION,
  SUPABASE_CONNECTOR_MANIFEST_VERSION,
  SUPABASE_POLICY_DECISION_VERSION
} from "../supabase/canonical.js";
import {
  KOJIMEM_ACTION_CERTIFICATE_VERSION,
  KOJIMEM_REQUEST_VERSION,
  KOJIMEM_WORKFLOW_ID
} from "../kojimem/canonical.js";
import { verifyOperatorRegistryRecord } from "../registry/email-registry.js";
import { verifyOperatorAdmissionManifest } from "../admission/operator-manifest.js";
import { Verifier, hashAttestationDocument } from "@tinfoilsh/verifier";

const OPERATOR_IDENTITY_BINDING_VERSION = "strata.operator_identity_binding.v1";
const EMAIL_CERTIFICATE_BUNDLE_VERSION = "strata.email.certificate_bundle.v1";
const SUPABASE_CERTIFICATE_BUNDLE_VERSION = "strata.supabase.certificate_bundle.v1";
const SUPABASE_POLICY_DENIAL_CERTIFICATE_VERSION = "strata.supabase.policy_denial_certificate.v1";
const SUPABASE_REQUEST_VERSION = "strata.supabase.request.v1";
const SUPABASE_RESULT_SUMMARY_VERSION = "strata.supabase.result_summary.v1";
const KOJIMEM_CERTIFICATE_BUNDLE_VERSION = "strata.kojimem.certificate_bundle.v1";
const KOJIMEM_POLICY_DENIAL_CERTIFICATE_VERSION = "strata.kojimem.policy_denial_certificate.v1";
const KOJIMEM_CONNECTOR_MANIFEST_VERSION = "strata.kojimem.connector_manifest.v1";
const MANAGED_AGENT_WITNESS_BUNDLE_VERSION = "attexa.managed_agent.witness_bundle.v1";
const MANAGED_AGENT_POLICY_DECISION_VERSION = "attexa.managed_agent.policy_decision.v1";
const MANAGED_AGENT_RECEIPT_VERSION = "turnstile.receipt.v1";
const MANAGED_AGENT_STATE_ROOT_PROTOCOL = "turnstile-state-root-v1";
const MANAGED_AGENT_GENESIS_ROOT = "0".repeat(64);

export async function verifyCertificateBundleUrl(bundleUrl) {
  const normalizedUrl = normalizeBundleUrl(bundleUrl);
  const bundle = await getJson(normalizedUrl);
  return verifyCertificateBundle(bundle, { sourceUrl: normalizedUrl });
}

export function normalizeBundleUrl(value) {
  const url = new URL(String(value || "").trim());
  url.hash = "";
  url.search = "";
  url.pathname = url.pathname.replace(/\/$/, "");
  if (/\/certificates\/[^/]+$/.test(url.pathname)) {
    url.pathname = `${url.pathname}/bundle`;
  }
  return url.toString();
}

export async function verifyCertificateBundle(bundle, { sourceUrl = "" } = {}) {
  if (!bundle?.version && bundle?.bundle?.version) {
    bundle = bundle.bundle;
  }
  if (bundle?.version === MANAGED_AGENT_WITNESS_BUNDLE_VERSION) {
    return verifyManagedAgentWitnessBundle(bundle, { sourceUrl });
  }
  if (bundle?.version === SUPABASE_CERTIFICATE_BUNDLE_VERSION || String(bundle?.certificate?.version || "").startsWith("strata.supabase.")) {
    return verifySupabaseCertificateBundle(bundle, { sourceUrl });
  }
  if (bundle?.version === KOJIMEM_CERTIFICATE_BUNDLE_VERSION || String(bundle?.certificate?.version || "").startsWith("strata.kojimem.")) {
    return verifyKojimemCertificateBundle(bundle, { sourceUrl });
  }
  return verifyEmailCertificateBundle(bundle, { sourceUrl });
}

async function verifyEmailCertificateBundle(bundle, { sourceUrl = "" } = {}) {
  const checks = [];
  const certificate = bundle.certificate;
  const registryArtifact = bundle.registry_epoch;
  const registryEpoch = registryArtifact?.registry_epoch;
  const registryTrustAnchor = registryArtifact?.registry_trust_anchor;
  const policyQuorum = bundle.policy_decision;
  const policyBundle = bundle.policy_bundle;
  const keyring = bundle.keyring || {};
  const transparencyLog = bundle.transparency_log || [];

  add(checks, "bundle.version", bundle.version === EMAIL_CERTIFICATE_BUNDLE_VERSION, { actual: bundle.version });
  add(checks, "certificate.present", Boolean(certificate), {});
  if (!certificate) {
    return result({ sourceUrl, certificate: null, checks });
  }

  add(checks, "certificate.digest", digestValue(withoutDigest(certificate)) === certificate.certificate_digest, {
    expected: certificate.certificate_digest,
    actual: digestValue(withoutDigest(certificate))
  });
  add(checks, "receipts.count", (bundle.receipts || []).length === certificate.proof?.receipt_count, {
    expected: certificate.proof?.receipt_count,
    actual: (bundle.receipts || []).length
  });

  const session = verifySession(bundle.receipts || [], keyring, {
    transparencyLogEntries: transparencyLog,
    requireAdmissionManifest: true,
    requireSideEffectQuorum: !certificate.denied,
    requireBoundaryQuorum: true,
    requireTransparencyLog: true
  });
  add(checks, "receipt_chain.session", session.ok, { errors: session.errors });

  const checkpoint = verifyCheckpoint(bundle.checkpoint, bundle.receipts || [], keyring, {
    transparencyLogEntries: transparencyLog,
    requireCheckpointQuorum: true,
    requireCheckpointTransparency: true
  });
  add(checks, "receipt_chain.checkpoint", checkpoint.ok, { errors: checkpoint.errors });

  const policyDigest = policyBundle ? policyBundleDigest(policyBundle) : null;
  add(checks, "policy_bundle.digest", policyDigest === certificate.policy?.policy_bundle_digest, {
    expected: certificate.policy?.policy_bundle_digest,
    actual: policyDigest
  });
  add(checks, "authority_pins.registry_epoch", certificate.authority_pins?.registry_epoch?.matched === true, certificate.authority_pins?.registry_epoch || {});
  add(checks, "authority_pins.registry_trust_anchor", certificate.authority_pins?.registry_trust_anchor?.matched === true, certificate.authority_pins?.registry_trust_anchor || {});
  add(checks, "authority_pins.policy_bundle", certificate.authority_pins?.policy_bundle?.matched === true, certificate.authority_pins?.policy_bundle || {});
  verifyDurablePublication(checks, bundle, sourceUrl);

  if (registryEpoch && registryTrustAnchor) {
    const trustAnchors = { [registryTrustAnchor.key_id]: registryTrustAnchor.public_key_pem };
    const registryVerification = verifyWitnessRegistryEpoch(registryEpoch, trustAnchors);
    add(checks, "registry.signature", registryVerification.ok, { errors: registryVerification.errors, key_id: registryTrustAnchor.key_id });
    add(checks, "registry.digest", witnessRegistryEpochDigest(registryEpoch) === certificate.registry?.registry_epoch_digest, {
      expected: certificate.registry?.registry_epoch_digest,
      actual: witnessRegistryEpochDigest(registryEpoch)
    });
    const l1Authority = verifyWitnessAuthority({
      receipts: bundle.receipts || [],
      checkpoint: bundle.checkpoint,
      keyring,
      registryEpoch,
      trustAnchors,
      workflowId: "email.send",
      policyHash: certificate.policy?.policy_bundle_digest,
      requiredTier: "mechanical"
    });
    add(checks, "registry.l1_witness_authority", l1Authority.ok, { errors: l1Authority.errors });
    const l2Authority = verifyPolicyQuorumAuthority({
      policyQuorum,
      registryEpoch,
      workflowId: "email.send",
      policyHash: certificate.policy?.policy_bundle_digest,
      requiredTier: "policy"
    });
    add(checks, "registry.l2_policy_authority", l2Authority.ok, { errors: l2Authority.errors });
  } else {
    add(checks, "registry.artifact_present", false, { registry_epoch: Boolean(registryEpoch), trust_anchor: Boolean(registryTrustAnchor) });
  }

  if (bundle.operator_registry?.operator_record && bundle.operator_registry?.registry_trust_anchor) {
    const operatorTrust = { [bundle.operator_registry.registry_trust_anchor.key_id]: bundle.operator_registry.registry_trust_anchor.public_key_pem };
    const operatorVerification = verifyOperatorRegistryRecord(bundle.operator_registry.operator_record, operatorTrust);
    add(checks, "operator_registry.signature", operatorVerification.ok, { errors: operatorVerification.errors });
    const expectedOperatorRecordDigest = certificate.operator_identity?.operator_registry_record_digest || certificate.admission?.operator_registry_record_digest;
    add(checks, "operator_registry.digest", digestValue(bundle.operator_registry.operator_record) === expectedOperatorRecordDigest, {
      expected: expectedOperatorRecordDigest,
      actual: digestValue(bundle.operator_registry.operator_record)
    });
  } else {
    add(checks, "operator_registry.artifact_present", false, {});
  }
  verifyOperatorIdentityBinding(checks, bundle, certificate);

  const runtimeVerifications = [];
  runtimeVerifications.push(verifyGatewayAttestation(checks, bundle));
  runtimeVerifications.push(...verifyL1Attestations(checks, bundle));
  await Promise.all(runtimeVerifications);

  return result({
    sourceUrl,
    certificate: {
      url: certificate.certificate_url,
      digest: certificate.certificate_digest,
      issued_at: certificate.issued_at,
      provider: certificate.provider?.provider,
      provider_message_id: certificate.provider?.provider_message_id,
      action: certificate.action,
      operator_identity: certificate.operator_identity || null,
      registry: certificate.registry || null,
      policy: certificate.policy,
      proof: certificate.proof,
      durable_publication: bundle.durable_publication || null
    },
    evidence: buildEvidenceSummary(bundle, certificate),
    checks
  });
}

function verifySupabaseCertificateBundle(bundle, { sourceUrl = "" } = {}) {
  const checks = [];
  const certificate = bundle.certificate;
  const connectorManifest = bundle.connector_manifest;
  const request = bundle.supabase_request;
  const policyDecision = bundle.policy_decision;
  const policyEvidence = supabasePolicyEvidence(policyDecision);
  const policyBundle = bundle.policy_bundle;
  const resultMetadata = bundle.supabase_result_metadata;
  const verification = bundle.verification;

  add(checks, "bundle.version", bundle.version === SUPABASE_CERTIFICATE_BUNDLE_VERSION, { actual: bundle.version });
  add(checks, "certificate.present", Boolean(certificate), {});
  if (!certificate) {
    return result({ sourceUrl, certificate: null, checks });
  }

  add(checks, "certificate.version", [SUPABASE_ACTION_CERTIFICATE_VERSION, SUPABASE_POLICY_DENIAL_CERTIFICATE_VERSION].includes(certificate.version), {
    actual: certificate.version
  });
  add(checks, "certificate.digest", digestValue(withoutDigest(certificate)) === certificate.certificate_digest, {
    expected: certificate.certificate_digest,
    actual: digestValue(withoutDigest(certificate))
  });
  verifyDurablePublication(checks, bundle, sourceUrl);

  add(checks, "supabase.connector_manifest.present", Boolean(connectorManifest), {});
  if (connectorManifest) {
    const manifestDigest = digestValue(connectorManifest);
    const manifestTool = (connectorManifest.tools || []).find((tool) => tool.strata_tool === certificate.action?.mcp_tool_name);
    add(checks, "supabase.connector_manifest.version", connectorManifest.version === SUPABASE_CONNECTOR_MANIFEST_VERSION, {
      expected: SUPABASE_CONNECTOR_MANIFEST_VERSION,
      actual: connectorManifest.version || null
    });
    add(checks, "supabase.connector_manifest.digest", manifestDigest === certificate.connector?.connector_manifest_digest, {
      expected: certificate.connector?.connector_manifest_digest || null,
      actual: manifestDigest
    });
    add(checks, "supabase.connector_manifest.tool_mapping", Boolean(manifestTool) && manifestTool.upstream_tool === certificate.action?.upstream_tool_name, {
      strata_tool: certificate.action?.mcp_tool_name || null,
      expected_upstream_tool: certificate.action?.upstream_tool_name || null,
      actual_upstream_tool: manifestTool?.upstream_tool || null
    });
    add(checks, "supabase.connector_binding.connector", connectorManifest.connector_id === certificate.connector?.connector_id && connectorManifest.connector_type === certificate.connector?.connector_type, {
      manifest_connector_id: connectorManifest.connector_id || null,
      certificate_connector_id: certificate.connector?.connector_id || null,
      manifest_connector_type: connectorManifest.connector_type || null,
      certificate_connector_type: certificate.connector?.connector_type || null
    });
    add(checks, "supabase.connector_binding.project_scope", connectorManifest.upstream?.project_ref === certificate.connector?.project_ref && connectorManifest.upstream?.project_ref === request?.project_ref, {
      manifest_project_ref: connectorManifest.upstream?.project_ref || null,
      certificate_project_ref: certificate.connector?.project_ref || null,
      request_project_ref: request?.project_ref || null
    });
    add(checks, "supabase.connector_binding.read_only", connectorManifest.upstream?.read_only === true && certificate.connector?.read_only === true && request?.read_only === true, {
      manifest_read_only: connectorManifest.upstream?.read_only ?? null,
      certificate_read_only: certificate.connector?.read_only ?? null,
      request_read_only: request?.read_only ?? null
    });
    add(checks, "supabase.connector_binding.features", sameArray(connectorManifest.upstream?.features, certificate.connector?.features) && sameArray(connectorManifest.upstream?.features, request?.features), {
      manifest_features: connectorManifest.upstream?.features || [],
      certificate_features: certificate.connector?.features || [],
      request_features: request?.features || []
    });
  }

  add(checks, "supabase.request.present", Boolean(request), {});
  if (request) {
    const requestDigest = digestValue(request);
    const inputDigest = digestValue(request.input || {});
    add(checks, "supabase.request.version", request.version === SUPABASE_REQUEST_VERSION, {
      expected: SUPABASE_REQUEST_VERSION,
      actual: request.version || null
    });
    add(checks, "supabase.request.digest", requestDigest === certificate.request?.request_digest && requestDigest === policyEvidence.request_digest, {
      certificate_request_digest: certificate.request?.request_digest || null,
      policy_request_digest: policyEvidence.request_digest || null,
      actual: requestDigest
    });
    add(checks, "supabase.request.input_digest", inputDigest === certificate.request?.input_digest, {
      expected: certificate.request?.input_digest || null,
      actual: inputDigest
    });
    add(checks, "supabase.request.tool_mapping", request.strata_tool_name === certificate.action?.mcp_tool_name && request.upstream_tool_name === certificate.action?.upstream_tool_name, {
      request_strata_tool: request.strata_tool_name || null,
      certificate_strata_tool: certificate.action?.mcp_tool_name || null,
      request_upstream_tool: request.upstream_tool_name || null,
      certificate_upstream_tool: certificate.action?.upstream_tool_name || null
    });
  }

  add(checks, "supabase.policy_bundle.present", Boolean(policyBundle), {});
  if (policyBundle) {
    const policyDigest = supabasePolicyBundleDigest(policyBundle);
    add(checks, "supabase.policy_bundle.version", policyBundle.version === SUPABASE_POLICY_BUNDLE_VERSION, {
      expected: SUPABASE_POLICY_BUNDLE_VERSION,
      actual: policyBundle.version || null
    });
    add(checks, "supabase.policy_bundle.digest", policyDigest === certificate.policy?.policy_bundle_digest && policyDigest === policyEvidence.policy_bundle_digest, {
      certificate_policy_bundle_digest: certificate.policy?.policy_bundle_digest || null,
      policy_decision_policy_bundle_digest: policyEvidence.policy_bundle_digest || null,
      actual: policyDigest
    });
    add(checks, "supabase.policy_bundle.identity", policyBundle.policy_id === certificate.policy?.policy_id && policyBundle.policy_id === policyEvidence.policy_id && policyBundle.epoch_id === certificate.policy?.policy_epoch_id && policyBundle.epoch_id === policyEvidence.policy_epoch_id, {
      policy_id: policyBundle.policy_id || null,
      certificate_policy_id: certificate.policy?.policy_id || null,
      policy_decision_policy_id: policyEvidence.policy_id || null,
      policy_epoch_id: policyBundle.epoch_id || null,
      certificate_policy_epoch_id: certificate.policy?.policy_epoch_id || null,
      policy_decision_policy_epoch_id: policyEvidence.policy_epoch_id || null
    });
  }

  add(checks, "supabase.policy_decision.present", Boolean(policyDecision), {});
  if (policyDecision) {
    const failedRules = (policyEvidence.rule_results || []).filter((item) => item.pass !== true);
    add(checks, "supabase.policy_decision.version", [SUPABASE_POLICY_DECISION_VERSION, SUPABASE_POLICY_QUORUM_VERSION].includes(policyDecision.version), {
      expected: [SUPABASE_POLICY_DECISION_VERSION, SUPABASE_POLICY_QUORUM_VERSION],
      actual: policyDecision.version || null
    });
    add(checks, "supabase.policy_decision.result", policyEvidence.decision === certificate.policy?.decision && sameArray(policyEvidence.reasons || [], certificate.policy?.reasons || []), {
      policy_decision: policyEvidence.decision || null,
      certificate_decision: certificate.policy?.decision || null,
      policy_reasons: policyEvidence.reasons || [],
      certificate_reasons: certificate.policy?.reasons || []
    });
    add(checks, "supabase.policy_decision.rule_consistency", policyEvidence.decision === "allow" ? failedRules.length === 0 : failedRules.length > 0, {
      decision: policyEvidence.decision || null,
      failed_rules: failedRules.map((item) => item.rule)
    });
    const expectedSqlDigest = policyEvidence.sql_digest || null;
    add(checks, "supabase.policy_decision.sql_digest", (certificate.request?.sql_digest || null) === expectedSqlDigest, {
      expected: expectedSqlDigest,
      actual: certificate.request?.sql_digest || null
    });
    if (policyEvidence.is_quorum) {
      add(checks, "supabase.policy_quorum.threshold", policyEvidence.allow_count >= policyEvidence.threshold === (policyEvidence.decision === "allow"), {
        allow_count: policyEvidence.allow_count,
        threshold: policyEvidence.threshold,
        decision: policyEvidence.decision || null
      });
      add(checks, "supabase.policy_quorum.signatures_present", (policyDecision.decisions || []).every((decision) => decision.subject && decision.signature?.signature), {
        decision_count: (policyDecision.decisions || []).length
      });
      add(checks, "supabase.policy_quorum.certificate_binding", sameArray(policyEvidence.decision_digests || [], certificate.policy?.decision_digests || []), {
        expected: certificate.policy?.decision_digests || [],
        actual: policyEvidence.decision_digests || []
      });
    }
  }

  add(checks, "supabase.verification.present", Boolean(verification), {});
  if (verification) {
    add(checks, "supabase.verification.policy", verification.policy?.decision === certificate.policy?.decision && verification.policy?.ok === (certificate.policy?.decision === "allow"), {
      verification_policy: verification.policy || null,
      certificate_policy_decision: certificate.policy?.decision || null
    });
    add(checks, "supabase.verification.ok", verification.ok === certificate.proof?.verified, {
      verification_ok: verification.ok ?? null,
      proof_verified: certificate.proof?.verified ?? null
    });
    add(checks, "supabase.proof.side_effect", certificate.proof?.side_effect_executed === (!certificate.denied && verification.upstream?.ok === true), {
      side_effect_executed: certificate.proof?.side_effect_executed ?? null,
      denied: certificate.denied === true,
      upstream_ok: verification.upstream?.ok ?? null
    });
  }
  add(checks, "supabase.denied_consistency", certificate.denied === (policyEvidence.decision === "deny"), {
    certificate_denied: certificate.denied === true,
    policy_decision: policyEvidence.decision || null
  });

  add(checks, "supabase.result_metadata.present", Boolean(resultMetadata), {});
  if (resultMetadata) {
    add(checks, "supabase.result_metadata.digest_only", isDigestOnlySupabaseResultMetadata(resultMetadata), {
      keys: Object.keys(resultMetadata)
    });
    if (certificate.result) {
      add(checks, "supabase.result_metadata.certificate_binding", digestValue(resultMetadata) === digestValue(certificate.result), {
        certificate_result_digest: digestValue(certificate.result),
        artifact_result_digest: digestValue(resultMetadata)
      });
    }
  }
  add(checks, "supabase.result_preview.digest_only", certificate.result_preview == null, {
    result_preview_present: certificate.result_preview != null
  });
  add(checks, "supabase.raw_live_payload_absent", !hasRawSupabasePayload(bundle), {});

  const phase1Scaffold = certificate.proof?.assurance_mode === "mcp-governance-proxy-phase1-scaffold" || certificate.proof?.assurance_mode === "policy_denied";
  if (phase1Scaffold) {
    add(checks, "supabase.receipt_profile.phase1_declared", (bundle.receipts || []).length === 0 && !bundle.checkpoint, {
      assurance_mode: certificate.proof?.assurance_mode || null,
      receipt_count: (bundle.receipts || []).length,
      checkpoint_present: Boolean(bundle.checkpoint)
    });
    warn(checks, "supabase.receipt_parity.pending", "This Supabase certificate verifies the phase-1 connector profile; full L1/L2 receipt parity is a separate profile upgrade.");
  } else {
    add(checks, "supabase.receipt_profile.witnessed", (bundle.receipts || []).length > 0 && Boolean(bundle.checkpoint), {
      assurance_mode: certificate.proof?.assurance_mode || null,
      receipt_count: (bundle.receipts || []).length,
      checkpoint_present: Boolean(bundle.checkpoint)
    });
    const keyring = bundle.keyring || {};
    const transparencyLog = bundle.transparency_log || [];
    const session = verifySession(bundle.receipts || [], keyring, {
      transparencyLogEntries: transparencyLog,
      requireAdmissionManifest: true,
      requireSideEffectQuorum: !certificate.denied,
      requireBoundaryQuorum: true,
      requireTransparencyLog: true
    });
    add(checks, "supabase.receipt_chain.session", session.ok, { errors: session.errors });
    const checkpoint = verifyCheckpoint(bundle.checkpoint, bundle.receipts || [], keyring, {
      transparencyLogEntries: transparencyLog,
      requireCheckpointQuorum: true,
      requireCheckpointTransparency: true
    });
    add(checks, "supabase.receipt_chain.checkpoint", checkpoint.ok, { errors: checkpoint.errors });
    if (bundle.registry_epoch?.registry_epoch && bundle.registry_epoch?.registry_trust_anchor) {
      const registryEpoch = bundle.registry_epoch.registry_epoch;
      const trustAnchors = { [bundle.registry_epoch.registry_trust_anchor.key_id]: bundle.registry_epoch.registry_trust_anchor.public_key_pem };
      const l1Authority = verifyWitnessAuthority({
        receipts: bundle.receipts || [],
        checkpoint: bundle.checkpoint,
        keyring,
        registryEpoch,
        trustAnchors,
        workflowId: "supabase.query",
        policyHash: certificate.policy?.policy_bundle_digest,
        requiredTier: "mechanical"
      });
      add(checks, "supabase.registry.l1_witness_authority", l1Authority.ok, { errors: l1Authority.errors });
      const l2Authority = verifyPolicyQuorumAuthority({
        policyQuorum: policyDecision,
        registryEpoch,
        workflowId: "supabase.query",
        policyHash: certificate.policy?.policy_bundle_digest,
        requiredTier: "policy"
      });
      add(checks, "supabase.registry.l2_policy_authority", l2Authority.ok, { errors: l2Authority.errors });
    } else {
      add(checks, "supabase.registry.artifact_present", false, { registry_epoch: Boolean(bundle.registry_epoch?.registry_epoch), trust_anchor: Boolean(bundle.registry_epoch?.registry_trust_anchor) });
    }
  }

  return result({
    sourceUrl,
    certificate: {
      url: certificate.certificate_url,
      digest: certificate.certificate_digest,
      issued_at: certificate.issued_at,
      action: certificate.action,
      connector: certificate.connector || null,
      request: certificate.request || null,
      policy: certificate.policy,
      proof: certificate.proof,
      result: certificate.result || null,
      durable_publication: bundle.durable_publication || null
    },
    evidence: buildSupabaseEvidenceSummary(bundle, certificate),
    checks
  });
}

function verifyKojimemCertificateBundle(bundle, { sourceUrl = "" } = {}) {
  const checks = [];
  const certificate = bundle.certificate;
  const connectorManifest = bundle.connector_manifest;
  const request = bundle.kojimem_request;
  const policyDecision = bundle.policy_decision;
  const policyEvidence = kojimemPolicyEvidence(policyDecision);
  const policyBundle = bundle.policy_bundle;
  const resultMetadata = bundle.kojimem_result_metadata;
  const verification = bundle.verification;

  add(checks, "bundle.version", bundle.version === KOJIMEM_CERTIFICATE_BUNDLE_VERSION, {
    expected: KOJIMEM_CERTIFICATE_BUNDLE_VERSION,
    actual: bundle.version
  });
  add(checks, "certificate.present", Boolean(certificate), {});
  if (!certificate) {
    return result({ sourceUrl, certificate: null, checks });
  }

  add(checks, "certificate.version", [KOJIMEM_ACTION_CERTIFICATE_VERSION, KOJIMEM_POLICY_DENIAL_CERTIFICATE_VERSION].includes(certificate.version), {
    expected: [KOJIMEM_ACTION_CERTIFICATE_VERSION, KOJIMEM_POLICY_DENIAL_CERTIFICATE_VERSION],
    actual: certificate.version
  });
  add(checks, "certificate.digest", digestValue(withoutDigest(certificate)) === certificate.certificate_digest, {
    expected: certificate.certificate_digest,
    actual: digestValue(withoutDigest(certificate))
  });
  verifyDurablePublication(checks, bundle, sourceUrl);

  add(checks, "kojimem.connector_manifest.present", Boolean(connectorManifest), {});
  if (connectorManifest) {
    const manifestDigest = digestValue(connectorManifest);
    const manifestTool = (connectorManifest.tools || []).find((tool) => tool.strata_tool === certificate.action?.mcp_tool_name);
    add(checks, "kojimem.connector_manifest.version", connectorManifest.version === KOJIMEM_CONNECTOR_MANIFEST_VERSION, {
      expected: KOJIMEM_CONNECTOR_MANIFEST_VERSION,
      actual: connectorManifest.version || null
    });
    add(checks, "kojimem.connector_manifest.digest", manifestDigest === certificate.connector?.connector_manifest_digest, {
      expected: certificate.connector?.connector_manifest_digest || null,
      actual: manifestDigest
    });
    add(checks, "kojimem.connector_manifest.tool_mapping", Boolean(manifestTool) && manifestTool.gateway_tool === certificate.action?.gateway_tool_name, {
      strata_tool: certificate.action?.mcp_tool_name || null,
      expected_gateway_tool: certificate.action?.gateway_tool_name || null,
      actual_gateway_tool: manifestTool?.gateway_tool || null
    });
    add(checks, "kojimem.connector_binding.connector", connectorManifest.connector_id === certificate.connector?.connector_id && connectorManifest.connector_type === certificate.connector?.connector_type, {
      manifest_connector_id: connectorManifest.connector_id || null,
      certificate_connector_id: certificate.connector?.connector_id || null,
      manifest_connector_type: connectorManifest.connector_type || null,
      certificate_connector_type: certificate.connector?.connector_type || null
    });
    add(checks, "kojimem.connector_binding.wallets", connectorManifest.agents?.originator?.wallet === certificate.connector?.agent_a_wallet && connectorManifest.agents?.delegate?.wallet === certificate.connector?.agent_b_wallet, {
      manifest_agent_a_wallet: connectorManifest.agents?.originator?.wallet || null,
      certificate_agent_a_wallet: certificate.connector?.agent_a_wallet || null,
      manifest_agent_b_wallet: connectorManifest.agents?.delegate?.wallet || null,
      certificate_agent_b_wallet: certificate.connector?.agent_b_wallet || null
    });
  }

  add(checks, "kojimem.request.present", Boolean(request), {});
  if (request) {
    const requestDigest = digestValue(request);
    add(checks, "kojimem.request.version", request.version === KOJIMEM_REQUEST_VERSION, {
      expected: KOJIMEM_REQUEST_VERSION,
      actual: request.version || null
    });
    add(checks, "kojimem.request.redacted_artifact_binding", requestDigest === digestValue(certificate.request?.redacted || {}), {
      certificate_redacted_digest: digestValue(certificate.request?.redacted || {}),
      actual: requestDigest
    });
    add(checks, "kojimem.request.full_digest_binding", certificate.request?.request_digest === policyEvidence.request_digest && certificate.request?.request_digest === certificate.request?.public_commitment?.request_digest, {
      certificate_request_digest: certificate.request?.request_digest || null,
      policy_request_digest: policyEvidence.request_digest || null,
      public_commitment_request_digest: certificate.request?.public_commitment?.request_digest || null
    });
    add(checks, "kojimem.request.workflow", request.workflow_id === KOJIMEM_WORKFLOW_ID && certificate.action?.workflow_id === KOJIMEM_WORKFLOW_ID, {
      request_workflow_id: request.workflow_id || null,
      certificate_workflow_id: certificate.action?.workflow_id || null
    });
    add(checks, "kojimem.request.digest_only_facts", !request.execution?.facts && !request.execution?.recall_question && Boolean(request.backpack?.facts_digest) && Boolean(request.recall?.question_digest), {
      raw_facts_present: Boolean(request.execution?.facts),
      raw_question_present: Boolean(request.execution?.recall_question),
      facts_digest: request.backpack?.facts_digest || null,
      question_digest: request.recall?.question_digest || null
    });
  }

  add(checks, "kojimem.policy_bundle.present", Boolean(policyBundle), {});
  if (policyBundle) {
    const policyDigest = kojimemPolicyBundleDigest(policyBundle);
    add(checks, "kojimem.policy_bundle.version", policyBundle.version === KOJIMEM_POLICY_BUNDLE_VERSION, {
      expected: KOJIMEM_POLICY_BUNDLE_VERSION,
      actual: policyBundle.version || null
    });
    add(checks, "kojimem.policy_bundle.digest", policyDigest === certificate.policy?.policy_bundle_digest && policyDigest === policyEvidence.policy_bundle_digest, {
      certificate_policy_bundle_digest: certificate.policy?.policy_bundle_digest || null,
      policy_decision_policy_bundle_digest: policyEvidence.policy_bundle_digest || null,
      actual: policyDigest
    });
    add(checks, "kojimem.policy_bundle.identity", policyBundle.policy_id === certificate.policy?.policy_id && policyBundle.policy_id === policyEvidence.policy_id && policyBundle.epoch_id === certificate.policy?.policy_epoch_id && policyBundle.epoch_id === policyEvidence.policy_epoch_id, {
      policy_id: policyBundle.policy_id || null,
      certificate_policy_id: certificate.policy?.policy_id || null,
      policy_decision_policy_id: policyEvidence.policy_id || null,
      policy_epoch_id: policyBundle.epoch_id || null,
      certificate_policy_epoch_id: certificate.policy?.policy_epoch_id || null,
      policy_decision_policy_epoch_id: policyEvidence.policy_epoch_id || null
    });
  }

  add(checks, "kojimem.policy_decision.present", Boolean(policyDecision), {});
  if (policyDecision) {
    const failedRules = (policyEvidence.rule_results || []).filter((item) => item.pass !== true);
    add(checks, "kojimem.policy_decision.version", policyDecision.version === KOJIMEM_POLICY_QUORUM_VERSION, {
      expected: KOJIMEM_POLICY_QUORUM_VERSION,
      actual: policyDecision.version || null
    });
    add(checks, "kojimem.policy_decision.result", policyEvidence.decision === certificate.policy?.decision && sameArray(policyEvidence.reasons || [], certificate.policy?.reasons || []), {
      policy_decision: policyEvidence.decision || null,
      certificate_decision: certificate.policy?.decision || null,
      policy_reasons: policyEvidence.reasons || [],
      certificate_reasons: certificate.policy?.reasons || []
    });
    add(checks, "kojimem.policy_decision.rule_consistency", policyEvidence.decision === "allow" ? failedRules.length === 0 : failedRules.length > 0, {
      decision: policyEvidence.decision || null,
      failed_rules: failedRules.map((item) => item.rule)
    });
    add(checks, "kojimem.policy_quorum.threshold", policyEvidence.allow_count >= policyEvidence.threshold === (policyEvidence.decision === "allow"), {
      allow_count: policyEvidence.allow_count,
      threshold: policyEvidence.threshold,
      decision: policyEvidence.decision || null
    });
    add(checks, "kojimem.policy_quorum.signatures_present", (policyDecision.decisions || []).every((decision) => decision.subject && decision.signature?.signature), {
      decision_count: (policyDecision.decisions || []).length
    });
    add(checks, "kojimem.policy_quorum.certificate_binding", sameArray(policyEvidence.decision_digests || [], certificate.policy?.decision_digests || []), {
      expected: certificate.policy?.decision_digests || [],
      actual: policyEvidence.decision_digests || []
    });
  }

  add(checks, "kojimem.verification.present", Boolean(verification), {});
  if (verification) {
    const verificationPolicyDecision = verification.policy?.decision || policyEvidence.decision || null;
    const verificationPolicyOk = verification.policy?.ok ?? (policyEvidence.decision === "allow");
    add(checks, "kojimem.verification.policy", verificationPolicyDecision === certificate.policy?.decision && verificationPolicyOk === (certificate.policy?.decision === "allow"), {
      verification_policy: verification.policy || null,
      certificate_policy_decision: certificate.policy?.decision || null
    });
    add(checks, "kojimem.verification.ok", verification.ok === certificate.proof?.verified, {
      verification_ok: verification.ok ?? null,
      proof_verified: certificate.proof?.verified ?? null
    });
    const executionOk = verification.execution?.ok ?? (resultMetadata?.status === "completed");
    add(checks, "kojimem.proof.side_effect", certificate.proof?.side_effect_executed === (!certificate.denied && executionOk === true), {
      side_effect_executed: certificate.proof?.side_effect_executed ?? null,
      denied: certificate.denied === true,
      execution_ok: executionOk
    });
  }

  add(checks, "kojimem.result_metadata.present", Boolean(resultMetadata), {});
  if (resultMetadata) {
    add(checks, "kojimem.result_metadata.certificate_binding", digestValue(resultMetadata) === digestValue(certificate.result || {}), {
      certificate_result_digest: digestValue(certificate.result || {}),
      artifact_result_digest: digestValue(resultMetadata)
    });
    add(checks, "kojimem.result_metadata.destroyed", resultMetadata.destroyed === true || certificate.denied === true, {
      destroyed: resultMetadata.destroyed ?? null,
      denied: certificate.denied === true
    });
    add(checks, "kojimem.result_metadata.settlement", resultMetadata.settlement?.protocol === "x402" && resultMetadata.settlement?.asset === "USDC", {
      protocol: resultMetadata.settlement?.protocol || null,
      asset: resultMetadata.settlement?.asset || null
    });
    add(checks, "kojimem.result_metadata.delegation", Boolean(resultMetadata.delegation_hash) && sameArray(resultMetadata.delegation_scope || [], ["destroy", "recall"]), {
      delegation_hash: resultMetadata.delegation_hash || null,
      delegation_scope: resultMetadata.delegation_scope || []
    });
  }

  const keyring = bundle.keyring || {};
  const transparencyLog = bundle.transparency_log || [];
  add(checks, "kojimem.receipt_profile.witnessed", (bundle.receipts || []).length > 0 && Boolean(bundle.checkpoint), {
    assurance_mode: certificate.proof?.assurance_mode || null,
    receipt_count: (bundle.receipts || []).length,
    checkpoint_present: Boolean(bundle.checkpoint)
  });
  const session = verifySession(bundle.receipts || [], keyring, {
    transparencyLogEntries: transparencyLog,
    requireAdmissionManifest: true,
    requireSideEffectQuorum: !certificate.denied,
    requireBoundaryQuorum: true,
    requireTransparencyLog: true
  });
  add(checks, "kojimem.receipt_chain.session", session.ok, { errors: session.errors });
  const checkpoint = verifyCheckpoint(bundle.checkpoint, bundle.receipts || [], keyring, {
    transparencyLogEntries: transparencyLog,
    requireCheckpointQuorum: true,
    requireCheckpointTransparency: true
  });
  add(checks, "kojimem.receipt_chain.checkpoint", checkpoint.ok, { errors: checkpoint.errors });

  if (bundle.registry_epoch?.registry_epoch && bundle.registry_epoch?.registry_trust_anchor) {
    const registryEpoch = bundle.registry_epoch.registry_epoch;
    const trustAnchors = { [bundle.registry_epoch.registry_trust_anchor.key_id]: bundle.registry_epoch.registry_trust_anchor.public_key_pem };
    const l1Authority = verifyWitnessAuthority({
      receipts: bundle.receipts || [],
      checkpoint: bundle.checkpoint,
      keyring,
      registryEpoch,
      trustAnchors,
      workflowId: KOJIMEM_WORKFLOW_ID,
      policyHash: certificate.policy?.policy_bundle_digest,
      requiredTier: "mechanical"
    });
    add(checks, "kojimem.registry.l1_witness_authority", l1Authority.ok, { errors: l1Authority.errors });
    const l2Authority = verifyPolicyQuorumAuthority({
      policyQuorum: policyDecision,
      registryEpoch,
      workflowId: KOJIMEM_WORKFLOW_ID,
      policyHash: certificate.policy?.policy_bundle_digest,
      requiredTier: "policy"
    });
    add(checks, "kojimem.registry.l2_policy_authority", l2Authority.ok, { errors: l2Authority.errors });
  } else {
    warn(checks, "kojimem.registry.artifact_present", "Kojimem bundle profile v0.1 does not include registry epoch artifacts; L1/L2 signed evidence and policy quorum are still verified from bundle artifacts.");
  }
  if (!bundle.operator_registry) {
    warn(checks, "kojimem.operator_registry.artifact_present", "Kojimem bundle profile v0.1 does not include operator registry artifacts; admission manifest signature is verified by receipt-chain checks.");
  }
  if (!bundle.gateway_attestation) {
    warn(checks, "kojimem.gateway_attestation.artifact_present", "Kojimem bundle profile v0.1 does not include observed gateway attestation artifacts; use the gateway's Tinfoil config repo release for runtime attestation verification.");
  }
  if (!bundle.l1_witness_attestations) {
    warn(checks, "kojimem.l1_attestation.artifact_present", "Kojimem bundle profile v0.1 does not include observed L1 attestation artifacts; witness signatures are verified through the receipt chain.");
  }

  return result({
    sourceUrl,
    certificate: {
      url: certificate.certificate_url,
      digest: certificate.certificate_digest,
      issued_at: certificate.issued_at,
      action: certificate.action,
      connector: certificate.connector || null,
      request: certificate.request || null,
      policy: certificate.policy,
      proof: certificate.proof,
      result: certificate.result || null,
      durable_publication: bundle.durable_publication || null
    },
    evidence: buildKojimemEvidenceSummary(bundle, certificate),
    checks
  });
}

function verifyManagedAgentWitnessBundle(bundle, { sourceUrl = "" } = {}) {
  const checks = [];
  const manifest = bundle.manifest || {};
  const receipts = Array.isArray(bundle.receipts) ? bundle.receipts : [];
  const evidence = Array.isArray(bundle.evidence) ? bundle.evidence : [];
  const keyring = bundle.keyring || {};
  const verifierProfile = bundle.verifier_profile || null;
  const receiptVerification = verifyManagedAgentReceipts(receipts, keyring, { expectedSessionId: manifest.chain_id || null });
  const evidenceVerification = verifyManagedAgentEvidence(receipts, evidence);
  const subjectVerification = verifyManagedAgentSubjects(receipts);
  const sessionCreatedReceipts = receipts.filter((receipt) => receipt.kind === "managed_agent.session.created");
  const toolRequestReceipts = receipts.filter((receipt) => receipt.kind === "managed_agent.tool.requested");
  const toolResultReceipts = receipts.filter((receipt) => receipt.kind === "managed_agent.tool.result_observed");
  const toolConfirmationReceipts = receipts.filter((receipt) => receipt.kind === "managed_agent.tool.confirmed");
  const policyReceipts = receipts.filter((receipt) => receipt.kind === "managed_agent.policy.evaluated");
  const generatedFileReceipts = receipts.filter((receipt) => receipt.kind === "managed_agent.file.generated");
  const policyPayloads = policyReceipts.map((receipt) => payloadForReceipt(receipt, evidence));
  const toolFlow = verifyManagedAgentToolFlow({ toolRequestReceipts, toolResultReceipts });
  const policySemantics = verifyManagedAgentPolicySemantics({ policyReceipts, policyPayloads, toolConfirmationReceipts, toolResultReceipts, evidence });
  const artifactSemantics = verifyManagedAgentArtifacts({ generatedFileReceipts, evidence });
  const sessionProfile = managedAgentSessionProfile(sessionCreatedReceipts);
  const expectedChainId = manifest.org_id && manifest.anthropic_session_id ? `org:${manifest.org_id}:session:${manifest.anthropic_session_id}` : null;
  const recomputedBundleDigest = digestValue(withoutBundleDigest(bundle));

  add(checks, "managed_agent.bundle.version", bundle.version === MANAGED_AGENT_WITNESS_BUNDLE_VERSION, {
    expected: MANAGED_AGENT_WITNESS_BUNDLE_VERSION,
    actual: bundle.version || null
  });
  add(checks, "managed_agent.bundle.digest", Boolean(bundle.bundle_digest) && bundle.bundle_digest === recomputedBundleDigest, {
    expected: bundle.bundle_digest || null,
    actual: recomputedBundleDigest
  });
  add(checks, "managed_agent.manifest.present", Boolean(bundle.manifest), {});
  add(checks, "managed_agent.manifest.workflow", manifest.workflow_id === "managed-agent.observed" && manifest.assurance_mode === "observed-l1", {
    workflow_id: manifest.workflow_id || null,
    assurance_mode: manifest.assurance_mode || null
  });
  add(checks, "managed_agent.manifest.session_binding", Boolean(expectedChainId) && manifest.chain_id === expectedChainId, {
    expected: expectedChainId,
    actual: manifest.chain_id || null
  });
  add(checks, "managed_agent.keyring.present", Object.keys(keyring).length > 0, {
    key_count: Object.keys(keyring).length
  });
  add(checks, "managed_agent.verifier_profile.present", Boolean(verifierProfile), {});
  if (verifierProfile) {
    add(checks, "managed_agent.verifier_profile.binding", verifierProfile.profile_id === manifest.profile_id && verifierProfile.workflow_id === manifest.workflow_id && verifierProfile.assurance_mode === manifest.assurance_mode, {
      verifier_profile_id: verifierProfile.profile_id || null,
      manifest_profile_id: manifest.profile_id || null,
      verifier_workflow_id: verifierProfile.workflow_id || null,
      manifest_workflow_id: manifest.workflow_id || null
    });
  }

  add(checks, "managed_agent.receipts.present", receipts.length > 0, { receipt_count: receipts.length });
  add(checks, "managed_agent.receipt_chain.signatures", receiptVerification.ok, {
    errors: receiptVerification.errors,
    receipt_count: receiptVerification.receipt_count,
    final_state_root: receiptVerification.final_state_root
  });
  add(checks, "managed_agent.receipt_chain.local_summary", !bundle.verification || bundle.verification.ok === receiptVerification.ok, {
    bundle_verification_ok: bundle.verification?.ok ?? null,
    verifier_ok: receiptVerification.ok
  });
  if (bundle.verification?.final_state_root) {
    add(checks, "managed_agent.receipt_chain.final_root", bundle.verification.final_state_root === receiptVerification.final_state_root, {
      expected: bundle.verification.final_state_root,
      actual: receiptVerification.final_state_root
    });
  }
  add(checks, "managed_agent.evidence.payload_digests", evidenceVerification.ok, {
    errors: evidenceVerification.errors,
    evidence_count: evidence.length
  });
  add(checks, "managed_agent.receipt_subjects.digest_binding", subjectVerification.ok, {
    errors: subjectVerification.errors
  });

  add(checks, "managed_agent.session.created", sessionCreatedReceipts.length > 0, {
    count: sessionCreatedReceipts.length,
    agent_profile_id: sessionProfile.agent_profile_id || null,
    policy_mode: sessionProfile.policy_mode || null
  });
  if (!sessionProfile.agent_profile_id) {
    warn(checks, "managed_agent.session.agent_profile", "No Agent Profile admission receipt was found; receipt-chain evidence still verifies but profile-specific admission metadata is absent.");
  }

  add(checks, "managed_agent.tool_flow.results_match_requests", toolFlow.ok, {
    errors: toolFlow.errors,
    tool_request_count: toolRequestReceipts.length,
    tool_result_count: toolResultReceipts.length
  });
  if (policyReceipts.length > 0) {
    add(checks, "managed_agent.l2.policy_receipts_present", true, { count: policyReceipts.length });
    add(checks, "managed_agent.l2.policy_decision_integrity", policySemantics.integrity.ok, {
      errors: policySemantics.integrity.errors
    });
    add(checks, "managed_agent.l2.denied_actions_not_executed", policySemantics.deniedActions.ok, {
      errors: policySemantics.deniedActions.errors
    });
    add(checks, "managed_agent.l2.denied_actions_confirmed_denied", policySemantics.deniedConfirmations.ok, {
      errors: policySemantics.deniedConfirmations.errors
    });
    if (policySemantics.deniedConfirmations.missing.length > 0) {
      warn(checks, "managed_agent.l2.denied_actions_pending_confirmation", `Denied policy decisions without user.tool_confirmation receipts: ${policySemantics.deniedConfirmations.missing.join(", ")}`);
    }
    if (policySemantics.remoteQuorum.count > 0) {
      add(checks, "managed_agent.l2.remote_quorum_threshold", policySemantics.remoteQuorum.ok, {
        errors: policySemantics.remoteQuorum.errors,
        remote_quorum_count: policySemantics.remoteQuorum.count
      });
      warn(checks, "managed_agent.l2.remote_quorum_signature_verification", "Remote Managed Agent policy quorum public keys are not embedded in this bundle profile; the verifier checks quorum threshold and digest binding but cannot yet re-verify remote policy signatures offline.");
    }
  } else {
    warn(checks, "managed_agent.l2.policy_receipts_present", "No Managed Agent L2 policy decision receipts are included; this bundle verifies observed-L1 evidence only.");
  }

  if (generatedFileReceipts.length > 0) {
    add(checks, "managed_agent.artifacts.generated_hashes", artifactSemantics.ok, {
      errors: artifactSemantics.errors,
      generated_file_count: generatedFileReceipts.length
    });
  } else {
    warn(checks, "managed_agent.artifacts.generated_hashes", "No generated artifact receipts are included in this bundle.");
  }
  verifyDurablePublication(checks, bundle, sourceUrl);

  const latestPolicy = policyPayloads.filter(Boolean).at(-1) || null;
  return result({
    sourceUrl,
    certificate: {
      url: sourceUrl || null,
      digest: bundle.bundle_digest || recomputedBundleDigest,
      issued_at: manifest.created_at || receipts[0]?.issued_at || null,
      action: {
        workflow_id: manifest.workflow_id || null,
        anthropic_session_id: manifest.anthropic_session_id || null,
        method: "Claude Managed Agents event stream"
      },
      policy: latestPolicy ? {
        decision: latestPolicy.decision || null,
        reason: latestPolicy.reason || null,
        policy_id: latestPolicy.policy_id || null,
        policy_epoch_id: latestPolicy.policy_epoch_id || null,
        policy_bundle_digest: latestPolicy.policy_bundle_digest || null,
        decision_source: latestPolicy.decision_source || null,
        policy_witness_quorum: managedAgentPolicyQuorumLabel(latestPolicy.remote_quorum)
      } : null,
      proof: {
        assurance_mode: manifest.assurance_mode || null,
        receipt_count: receipts.length,
        final_state_root: receiptVerification.final_state_root,
        verified: receiptVerification.ok,
        policy_decision_count: policyReceipts.length,
        generated_artifact_count: generatedFileReceipts.length
      },
      durable_publication: bundle.durable_publication || null
    },
    evidence: buildManagedAgentEvidenceSummary({
      bundle,
      manifest,
      receipts,
      keyring,
      receiptVerification,
      sessionProfile,
      policyPayloads,
      generatedFileReceipts,
      toolRequestReceipts,
      toolResultReceipts,
      toolConfirmationReceipts
    }),
    checks
  });
}

export function renderMarkdownReport(report) {
  const verdict = report.ok ? "VALID" : "INVALID";
  const lines = [
    `# Strata Certificate Verification: ${verdict}`,
    "",
    `- Source: ${report.source_url || "(bundle object)"}`,
    `- Certificate: ${report.certificate?.url || "missing"}`,
    `- Digest: ${report.certificate?.digest || "missing"}`,
    `- Summary: ${report.summary.pass} pass, ${report.summary.warn} warn, ${report.summary.fail} fail`,
    `- L1 quorum: ${report.evidence?.l1?.quorum || "unknown"}`,
    `- L1 witnesses: ${report.evidence?.l1?.witness_count ?? 0}`,
    `- Operator: ${report.evidence?.operator?.operator_id || "unknown"}`,
    `- Durable bundle: ${report.evidence?.durable_publication?.bundle_url || "not published"}`,
    "",
    "## Checks",
    ""
  ];
  for (const check of report.checks) {
    const marker = check.severity === "fail" ? "FAIL" : check.severity === "warn" ? "WARN" : "PASS";
    lines.push(`- ${marker}: ${check.name}`);
    if (check.error) {
      lines.push(`  Error: ${check.error}`);
    }
    if (Array.isArray(check.errors) && check.errors.length > 0) {
      lines.push(`  Errors: ${check.errors.join("; ")}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

function verifyDurablePublication(checks, bundle, sourceUrl) {
  const publication = bundle.durable_publication;
  if (!publication) {
    warn(checks, "durable_publication.present", "No durable publication metadata is included; local or legacy gateway bundles may still verify but are not durable evidence URLs.");
    return;
  }
  add(checks, "durable_publication.present", true, {
    backend: publication.backend || null,
    scope: publication.scope || null,
    bundle_url: publication.bundle_url || null
  });
  add(checks, "durable_publication.complete_bundle_only", publication.scope === "complete_bundle_only", {
    expected: "complete_bundle_only",
    actual: publication.scope || null
  });
  add(checks, "durable_publication.no_overwrite", publication.no_overwrite === true, {
    no_overwrite: publication.no_overwrite === true,
    retention_mode: publication.retention_mode || null
  });
  if (sourceUrl && publication.bundle_url) {
    add(checks, "durable_publication.source_url", normalizeBundleUrl(publication.bundle_url) === sourceUrl, {
      expected: normalizeBundleUrl(publication.bundle_url),
      actual: sourceUrl
    });
  }
}

function withoutBundleDigest(bundle) {
  const { bundle_digest, ...rest } = bundle || {};
  return rest;
}

function verifyManagedAgentReceipts(receipts, keyring, { expectedSessionId = null } = {}) {
  const errors = [];
  let previousRoot = MANAGED_AGENT_GENESIS_ROOT;
  let finalStateRoot = previousRoot;

  if (!Array.isArray(receipts)) {
    return { ok: false, errors: ["receipts must be an array"], receipt_count: 0, final_state_root: finalStateRoot };
  }

  for (let index = 0; index < receipts.length; index += 1) {
    const receipt = receipts[index] || {};
    try {
      if (receipt.version !== MANAGED_AGENT_RECEIPT_VERSION) errors.push(`receipt ${index} invalid version: ${receipt.version}`);
      if (expectedSessionId && receipt.session_id !== expectedSessionId) errors.push(`receipt ${index} session_id mismatch`);
      if (receipt.prev_state_root !== previousRoot) errors.push(`receipt ${index} prev_state_root mismatch`);
      if (receipt.step_index !== index) errors.push(`receipt ${index} step_index mismatch`);
      const expectedRoot = computeManagedAgentStateRoot(receipt);
      if (receipt.state_root !== expectedRoot) errors.push(`receipt ${index} state_root mismatch`);
      if (!Array.isArray(receipt.signatures) || receipt.signatures.length === 0) {
        errors.push(`receipt ${index} missing signatures`);
      }
      for (const signature of receipt.signatures || []) {
        const publicKey = keyring[signature.key_id];
        if (!publicKey) {
          errors.push(`receipt ${index} unknown signer ${signature.key_id}`);
        } else if (!verifyEd25519(managedAgentReceiptSigningMessage(receipt), signature.sig, publicKey)) {
          errors.push(`receipt ${index} invalid signature ${signature.key_id}`);
        }
      }
      previousRoot = receipt.state_root;
      finalStateRoot = receipt.state_root;
    } catch (error) {
      errors.push(`receipt ${index} verification error: ${error.message}`);
    }
  }

  return { ok: errors.length === 0, errors, receipt_count: receipts.length, final_state_root: finalStateRoot };
}

function computeManagedAgentStateRoot(receipt) {
  return digestValue({
    protocol: MANAGED_AGENT_STATE_ROOT_PROTOCOL,
    prev_state_root: receipt.prev_state_root,
    payload_digest: managedAgentReceiptPayloadDigest(receipt),
    signatures: receipt.signatures || []
  });
}

function managedAgentReceiptSigningMessage(receipt) {
  return `${MANAGED_AGENT_RECEIPT_VERSION}\n${managedAgentReceiptPayloadDigest(receipt)}`;
}

function managedAgentReceiptPayloadDigest(receipt) {
  return digestValue(managedAgentReceiptPayload(receipt));
}

function managedAgentReceiptPayload(receipt) {
  const { signatures: _signatures, state_root: _stateRoot, ...payload } = receipt || {};
  return payload;
}

function verifyManagedAgentEvidence(receipts, evidence) {
  const errors = [];
  const evidenceByKey = managedAgentEvidenceByKey(evidence);
  for (let index = 0; index < receipts.length; index += 1) {
    const receipt = receipts[index];
    const eventKey = receipt?.body?.event_key;
    if (!eventKey) {
      errors.push(`receipt ${index} missing event_key`);
      continue;
    }
    const item = evidenceByKey.get(eventKey);
    if (!item) {
      errors.push(`receipt ${index} missing evidence for ${eventKey}`);
      continue;
    }
    if (item.payload_digest !== receipt.body?.payload_digest) {
      errors.push(`receipt ${index} evidence payload_digest mismatch`);
    }
    if (Object.prototype.hasOwnProperty.call(item, "payload") && digestValue(item.payload) !== receipt.body?.payload_digest) {
      errors.push(`receipt ${index} evidence payload hash mismatch`);
    }
  }
  return { ok: errors.length === 0, errors };
}

function verifyManagedAgentSubjects(receipts) {
  const errors = [];
  for (let index = 0; index < receipts.length; index += 1) {
    const receipt = receipts[index];
    const subject = receipt?.body?.subject;
    if (!subject) {
      errors.push(`receipt ${index} missing subject`);
      continue;
    }
    if (digestValue(subject) !== receipt.body?.subject_digest) errors.push(`receipt ${index} subject_digest mismatch`);
    if (subject.payload_digest !== receipt.body?.payload_digest) errors.push(`receipt ${index} subject payload_digest mismatch`);
    if (subject.session_id !== receipt.session_id) errors.push(`receipt ${index} subject session_id mismatch`);
    if (subject.step_index !== receipt.step_index) errors.push(`receipt ${index} subject step_index mismatch`);
    if (subject.receipt_class !== receipt.kind) errors.push(`receipt ${index} subject receipt_class mismatch`);
    if (subject.source?.event_type !== receipt.body?.event_type) errors.push(`receipt ${index} subject event_type mismatch`);
    if ((subject.source?.event_id || null) !== (receipt.body?.event_id || null)) errors.push(`receipt ${index} subject event_id mismatch`);
  }
  return { ok: errors.length === 0, errors };
}

function managedAgentEvidenceByKey(evidence) {
  return new Map((Array.isArray(evidence) ? evidence : []).filter((item) => item?.event_key).map((item) => [item.event_key, item]));
}

function payloadForReceipt(receipt, evidence) {
  const eventKey = receipt?.body?.event_key;
  if (!eventKey) return null;
  return managedAgentEvidenceByKey(evidence).get(eventKey)?.payload || null;
}

function managedAgentSessionProfile(sessionCreatedReceipts) {
  const receipt = sessionCreatedReceipts.at(-1) || null;
  const summary = receipt?.body?.typed_summary || {};
  return {
    agent_profile_id: summary.profile_id || null,
    policy_mode: summary.policy_mode || null,
    skill_ids: summary.skill_ids || [],
    file_count: summary.file_count || 0,
    github_repo_count: summary.github_repo_count || 0
  };
}

function verifyManagedAgentToolFlow({ toolRequestReceipts, toolResultReceipts }) {
  const errors = [];
  const requestIds = new Set(toolRequestReceipts.map((receipt) => receipt.body?.event_id).filter(Boolean));
  for (const receipt of toolResultReceipts) {
    const summary = receipt.body?.typed_summary || {};
    const toolUseId = summary.tool_use_id || summary.mcp_tool_use_id || summary.custom_tool_use_id || null;
    if (toolUseId && !requestIds.has(toolUseId)) {
      errors.push(`tool result at step ${receipt.step_index} references unknown request ${toolUseId}`);
    }
  }
  return { ok: errors.length === 0, errors };
}

function verifyManagedAgentPolicySemantics({ policyReceipts, policyPayloads, toolConfirmationReceipts, toolResultReceipts, evidence }) {
  const integrityErrors = [];
  const deniedExecutionErrors = [];
  const deniedConfirmationErrors = [];
  const missingDeniedConfirmations = [];
  const remoteQuorumErrors = [];
  const confirmationsByToolUse = new Map();
  const resultsByToolUse = new Map();

  for (const receipt of toolConfirmationReceipts) {
    const payload = payloadForReceipt(receipt, evidence);
    const toolUseId = payload?.tool_use_id || receipt.body?.typed_summary?.tool_use_id || null;
    if (toolUseId) confirmationsByToolUse.set(toolUseId, payload || receipt.body?.typed_summary || {});
  }
  for (const receipt of toolResultReceipts) {
    const summary = receipt.body?.typed_summary || {};
    const payload = payloadForReceipt(receipt, evidence);
    const toolUseId = summary.tool_use_id || summary.mcp_tool_use_id || summary.custom_tool_use_id || null;
    if (!toolUseId) continue;
    if (!resultsByToolUse.has(toolUseId)) resultsByToolUse.set(toolUseId, []);
    resultsByToolUse.get(toolUseId).push({ receipt, payload });
  }

  let remoteQuorumCount = 0;
  for (let index = 0; index < policyReceipts.length; index += 1) {
    const receipt = policyReceipts[index];
    const payload = policyPayloads[index] || null;
    const summary = receipt.body?.typed_summary || {};
    if (!payload) {
      integrityErrors.push(`policy receipt ${receipt.step_index} missing evidence payload`);
      continue;
    }
    if (payload.version !== MANAGED_AGENT_POLICY_DECISION_VERSION) integrityErrors.push(`policy receipt ${receipt.step_index} invalid decision version: ${payload.version}`);
    if (payload.request && digestValue(payload.request) !== payload.request_digest) integrityErrors.push(`policy receipt ${receipt.step_index} request_digest mismatch`);
    if (summary.decision !== payload.decision) integrityErrors.push(`policy receipt ${receipt.step_index} typed decision mismatch`);
    if (summary.policy_bundle_digest !== payload.policy_bundle_digest) integrityErrors.push(`policy receipt ${receipt.step_index} policy_bundle_digest mismatch`);
    if ((summary.event_id || null) !== (payload.event_id || null)) integrityErrors.push(`policy receipt ${receipt.step_index} event_id mismatch`);

    if (payload.decision === "deny" && payload.event_id) {
      for (const result of resultsByToolUse.get(payload.event_id) || []) {
        if (result.receipt.step_index > receipt.step_index && result.payload?.is_error !== true) {
          deniedExecutionErrors.push(`denied tool ${payload.event_id} has non-error tool result receipt after denial`);
        }
      }
      const confirmation = confirmationsByToolUse.get(payload.event_id);
      if (!confirmation) {
        missingDeniedConfirmations.push(payload.event_id);
      } else if (confirmation.result !== "deny") {
        deniedConfirmationErrors.push(`denied tool ${payload.event_id} has non-deny user.tool_confirmation result: ${confirmation.result}`);
      }
    }

    if (payload.remote_quorum) {
      remoteQuorumCount += 1;
      const quorum = payload.remote_quorum;
      if (quorum.decision !== payload.decision) remoteQuorumErrors.push(`policy receipt ${receipt.step_index} remote quorum decision mismatch`);
      if (quorum.request_digest !== payload.request_digest) remoteQuorumErrors.push(`policy receipt ${receipt.step_index} remote quorum request_digest mismatch`);
      const threshold = Number(quorum.threshold || 0);
      const countForDecision = payload.decision === "deny" ? quorum.deny_count : payload.decision === "allow" ? quorum.allow_count : quorum.requires_human_count;
      if (!threshold || Number(countForDecision || 0) < threshold) remoteQuorumErrors.push(`policy receipt ${receipt.step_index} remote quorum threshold not met`);
      if (!(quorum.decisions || []).every((decision) => decision.subject && decision.signature?.signature)) remoteQuorumErrors.push(`policy receipt ${receipt.step_index} remote quorum decisions missing subject/signature`);
    }
  }

  return {
    integrity: { ok: integrityErrors.length === 0, errors: integrityErrors },
    deniedActions: { ok: deniedExecutionErrors.length === 0, errors: deniedExecutionErrors },
    deniedConfirmations: { ok: deniedConfirmationErrors.length === 0, errors: deniedConfirmationErrors, missing: missingDeniedConfirmations },
    remoteQuorum: { ok: remoteQuorumErrors.length === 0, errors: remoteQuorumErrors, count: remoteQuorumCount }
  };
}

function verifyManagedAgentArtifacts({ generatedFileReceipts, evidence }) {
  const errors = [];
  for (const receipt of generatedFileReceipts) {
    const payload = payloadForReceipt(receipt, evidence);
    const summary = receipt.body?.typed_summary || {};
    if (!payload) {
      errors.push(`generated file receipt ${receipt.step_index} missing evidence payload`);
      continue;
    }
    if (payload.content_sha256 !== summary.content_sha256) errors.push(`generated file receipt ${receipt.step_index} content_sha256 mismatch`);
    if (summary.downloadable === true && !isSha256Hex(summary.content_sha256)) errors.push(`generated file receipt ${receipt.step_index} downloadable artifact missing sha256`);
    if (payload.file?.id && summary.file_id && payload.file.id !== summary.file_id) errors.push(`generated file receipt ${receipt.step_index} file_id mismatch`);
  }
  return { ok: errors.length === 0, errors };
}

function isSha256Hex(value) {
  return /^[a-f0-9]{64}$/i.test(String(value || ""));
}

function managedAgentPolicyQuorumLabel(quorum) {
  if (!quorum) return null;
  const count = quorum.decision === "deny" ? quorum.deny_count : quorum.decision === "allow" ? quorum.allow_count : quorum.requires_human_count;
  return `${count || 0}-of-${quorum.total_witnesses || 0}`;
}

function buildManagedAgentEvidenceSummary({ bundle, manifest, receipts, keyring, receiptVerification, sessionProfile, policyPayloads, generatedFileReceipts, toolRequestReceipts, toolResultReceipts, toolConfirmationReceipts }) {
  const validPolicyPayloads = policyPayloads.filter(Boolean);
  const latestPolicy = validPolicyPayloads.at(-1) || null;
  return {
    managed_agent: {
      anthropic_session_id: manifest.anthropic_session_id || null,
      chain_id: manifest.chain_id || null,
      workflow_id: manifest.workflow_id || null,
      witness_profile_id: manifest.profile_id || null,
      agent_profile_id: sessionProfile.agent_profile_id || null,
      policy_mode: sessionProfile.policy_mode || null,
      skill_ids: sessionProfile.skill_ids || [],
      receipt_count: receipts.length,
      final_state_root: receiptVerification.final_state_root,
      tool_request_count: toolRequestReceipts.length,
      tool_result_count: toolResultReceipts.length,
      tool_confirmation_count: toolConfirmationReceipts.length,
      policy_decision_count: validPolicyPayloads.length,
      generated_artifact_count: generatedFileReceipts.length
    },
    action: {
      tool: "managed_agent.session",
      provider: "Claude Managed Agents",
      provider_status: latestPolicy?.decision || "observed",
      side_effect_executed: false
    },
    l1: {
      quorum: `1-of-${Object.keys(keyring).length || 1} local observer`,
      witness_count: Object.keys(keyring).length,
      observed_attestation_count: 0,
      receipt_count: receipts.length,
      checkpoint_present: receipts.some((receipt) => receipt.kind === "managed_agent.session.checkpoint"),
      final_state_root: receiptVerification.final_state_root
    },
    l2: latestPolicy ? {
      policy_decision: latestPolicy.decision || null,
      policy_witness_quorum: managedAgentPolicyQuorumLabel(latestPolicy.remote_quorum) || (latestPolicy.decision_source === "local" ? "local evaluator" : null),
      policy_epoch_id: latestPolicy.policy_epoch_id || null,
      policy_bundle_digest: latestPolicy.policy_bundle_digest || null,
      tier: latestPolicy.decision_source || "local"
    } : null,
    artifacts: {
      generated_count: generatedFileReceipts.length,
      files: generatedFileReceipts.map((receipt) => ({
        file_id: receipt.body?.typed_summary?.file_id || null,
        filename: receipt.body?.typed_summary?.filename || null,
        content_sha256: receipt.body?.typed_summary?.content_sha256 || null,
        downloadable: receipt.body?.typed_summary?.downloadable === true
      }))
    },
    operator: {
      operator_id: "local-authenticated-demo-user",
      tenant_id: manifest.org_id || null,
      assistant_id: sessionProfile.agent_profile_id || null
    },
    durable_publication: bundle.durable_publication ? {
      backend: bundle.durable_publication.backend || null,
      scope: bundle.durable_publication.scope || null,
      bundle_url: bundle.durable_publication.bundle_url || null,
      key: bundle.durable_publication.key || null,
      retention_mode: bundle.durable_publication.retention_mode || null,
      no_overwrite: bundle.durable_publication.no_overwrite === true
    } : null
  };
}

function buildEvidenceSummary(bundle, certificate) {
  const l1Witnesses = certificate.tinfoil_attestation?.l1_witnesses || [];
  const observedL1 = bundle.l1_witness_attestations?.witnesses || [];
  const gateway = certificate.tinfoil_attestation?.gateway || null;
  return {
    action: {
      tool: certificate.action?.mcp_tool_name || null,
      provider: certificate.provider?.provider || null,
      provider_message_id: certificate.provider?.provider_message_id || null,
      provider_status: certificate.provider?.provider_status || null,
      side_effect_executed: !certificate.denied && certificate.proof?.verified === true
    },
    l1: {
      quorum: certificate.proof?.mechanical_witness_quorum || null,
      witness_count: l1Witnesses.length,
      observed_attestation_count: observedL1.length,
      distinct_config_repos: new Set(l1Witnesses.map((witness) => witness.config_repo).filter(Boolean)).size,
      witnesses: l1Witnesses.map((witness) => ({
        witness_id: witness.witness_id || witness.container_name || null,
        config_repo: witness.config_repo || null,
        config_tag: witness.config_tag || null,
        release_digest: witness.observed_attestation?.release_digest || witness.attestation_digest || null,
        attestation_digest: witness.attestation_digest || null,
        attestation_url: witness.attestation_ref || null,
        debug_mode: witness.debug_mode === true
      }))
    },
    l2: {
      policy_decision: certificate.policy?.decision || null,
      policy_witness_quorum: certificate.policy?.policy_witness_quorum || null,
      policy_epoch_id: certificate.policy?.policy_epoch_id || null,
      policy_bundle_digest: certificate.policy?.policy_bundle_digest || null
    },
    gateway: gateway ? {
      container_name: gateway.container_name || null,
      config_repo: gateway.config_repo || null,
      config_tag: gateway.config_tag || null,
      image_digest: gateway.image_digest || null,
      release_digest: gateway.observed_attestation?.release_digest || gateway.attestation_digest || null,
      attestation_digest: gateway.attestation_digest || null,
      debug_mode: gateway.debug_mode === true
    } : null,
    operator: certificate.operator_identity ? {
      operator_id: certificate.operator_identity.operator_id || null,
      tenant_id: certificate.operator_identity.tenant_id || null,
      operator_key_id: certificate.operator_identity.operator_key_id || null,
      workflow_id: certificate.operator_identity.workflow_id || null,
      tool_id: certificate.operator_identity.tool_id || null,
      status_at_action_time: certificate.operator_identity.status_at_action_time || null,
      registry_authorized: certificate.operator_identity.registry_authorized === true,
      signature_verified: certificate.operator_identity.signature_verified === true
    } : null,
    registry: certificate.registry ? {
      registry_epoch_id: certificate.registry.registry_epoch_id || null,
      registry_epoch_digest: certificate.registry.registry_epoch_digest || null,
      registry_authority_key_id: certificate.registry.registry_authority_key_id || null,
      policy_bundle_digest: certificate.registry.policy_bundle_digest || null
    } : null,
    durable_publication: bundle.durable_publication ? {
      backend: bundle.durable_publication.backend || null,
      scope: bundle.durable_publication.scope || null,
      bundle_url: bundle.durable_publication.bundle_url || null,
      key: bundle.durable_publication.key || null,
      retention_mode: bundle.durable_publication.retention_mode || null,
      no_overwrite: bundle.durable_publication.no_overwrite === true
    } : null
  };
}

function buildSupabaseEvidenceSummary(bundle, certificate) {
  const gateway = certificate.tinfoil_attestation?.gateway || null;
  const l1Witnesses = certificate.tinfoil_attestation?.l1_witnesses || [];
  const observedL1 = bundle.l1_witness_attestations?.witnesses || [];
  return {
    action: {
      tool: certificate.action?.mcp_tool_name || null,
      upstream_tool: certificate.action?.upstream_tool_name || null,
      method: certificate.action?.method || null,
      side_effect_executed: certificate.proof?.side_effect_executed === true
    },
    connector: certificate.connector ? {
      connector_id: certificate.connector.connector_id || null,
      connector_type: certificate.connector.connector_type || null,
      project_ref: certificate.connector.project_ref || null,
      read_only: certificate.connector.read_only === true,
      features: certificate.connector.features || [],
      upstream_origin: certificate.connector.upstream_origin || null,
      connector_manifest_digest: certificate.connector.connector_manifest_digest || null,
      credential_fingerprint_present: Boolean(certificate.connector.credential_fingerprint)
    } : null,
    l1: {
      quorum: certificate.proof?.mechanical_witness_quorum || certificate.proof?.mechanical_boundary_quorum || null,
      witness_count: l1Witnesses.length,
      observed_attestation_count: observedL1.length,
      receipt_count: (bundle.receipts || []).length,
      checkpoint_present: Boolean(bundle.checkpoint)
    },
    l2: {
      policy_decision: certificate.policy?.decision || null,
      policy_witness_quorum: certificate.policy?.policy_witness_quorum || null,
      policy_epoch_id: certificate.policy?.policy_epoch_id || null,
      policy_bundle_digest: certificate.policy?.policy_bundle_digest || null,
      tier: certificate.policy?.tier || null
    },
    gateway: gateway ? {
      container_name: gateway.container_name || null,
      config_repo: gateway.config_repo || null,
      config_tag: gateway.config_tag || null,
      image_digest: gateway.image_digest || null,
      attestation_digest: gateway.attestation_digest || null,
      debug_mode: gateway.debug_mode === true
    } : null,
    operator: certificate.session ? {
      operator_id: certificate.session.operator_id || null,
      tenant_id: certificate.session.tenant_id || null,
      assistant_id: certificate.session.assistant_id || null
    } : null,
    durable_publication: bundle.durable_publication ? {
      backend: bundle.durable_publication.backend || null,
      scope: bundle.durable_publication.scope || null,
      bundle_url: bundle.durable_publication.bundle_url || null,
      key: bundle.durable_publication.key || null,
      retention_mode: bundle.durable_publication.retention_mode || null,
      no_overwrite: bundle.durable_publication.no_overwrite === true
    } : null
  };
}

function buildKojimemEvidenceSummary(bundle, certificate) {
  const result = certificate.result || {};
  return {
    action: {
      tool: certificate.action?.mcp_tool_name || null,
      workflow_id: certificate.action?.workflow_id || null,
      method: certificate.action?.method || null,
      side_effect_executed: certificate.proof?.side_effect_executed === true
    },
    connector: certificate.connector ? {
      connector_id: certificate.connector.connector_id || null,
      connector_type: certificate.connector.connector_type || null,
      api_base_url: certificate.connector.api_base_url || null,
      network: certificate.connector.network || null,
      agent_a_wallet: certificate.connector.agent_a_wallet || null,
      agent_b_wallet: certificate.connector.agent_b_wallet || null,
      connector_manifest_digest: certificate.connector.connector_manifest_digest || null
    } : null,
    l1: {
      quorum: certificate.proof?.mechanical_witness_quorum || null,
      witness_count: Number(String(certificate.proof?.mechanical_witness_quorum || "0-of-0").split("-of-")[1] || 0),
      observed_attestation_count: 0,
      receipt_count: (bundle.receipts || []).length,
      checkpoint_present: Boolean(bundle.checkpoint)
    },
    l2: {
      policy_decision: certificate.policy?.decision || null,
      policy_witness_quorum: certificate.policy?.policy_witness_quorum || null,
      policy_epoch_id: certificate.policy?.policy_epoch_id || null,
      policy_bundle_digest: certificate.policy?.policy_bundle_digest || null,
      tier: certificate.policy?.tier || null
    },
    gateway: null,
    operator: certificate.session ? {
      operator_id: certificate.session.operator_id || null,
      tenant_id: certificate.session.tenant_id || null,
      assistant_id: certificate.session.assistant_id || null
    } : null,
    backpack: {
      memory_id: result.memory_id || null,
      delegation_hash: result.delegation_hash || null,
      delegation_scope: result.delegation_scope || [],
      destroyed: result.destroyed === true
    },
    settlement: result.settlement || null,
    durable_publication: bundle.durable_publication ? {
      backend: bundle.durable_publication.backend || null,
      scope: bundle.durable_publication.scope || null,
      bundle_url: bundle.durable_publication.bundle_url || null,
      key: bundle.durable_publication.key || null,
      retention_mode: bundle.durable_publication.retention_mode || null,
      no_overwrite: bundle.durable_publication.no_overwrite === true
    } : null
  };
}

function supabasePolicyEvidence(policyArtifact) {
  if (!policyArtifact) {
    return {};
  }
  if (policyArtifact.version === SUPABASE_POLICY_QUORUM_VERSION) {
    const firstSubject = policyArtifact.decisions?.[0]?.subject || {};
    const reasons = policyArtifact.deny_reasons || [...new Set((policyArtifact.decisions || []).flatMap((decision) => decision.subject?.reasons || []))];
    return {
      is_quorum: true,
      version: policyArtifact.version,
      policy_id: policyArtifact.policy_id,
      policy_epoch_id: policyArtifact.policy_epoch_id,
      policy_bundle_digest: policyArtifact.policy_bundle_digest,
      decision: policyArtifact.decision,
      reasons,
      rule_results: firstSubject.rule_results || [],
      request_digest: policyArtifact.request_digest || firstSubject.request_digest || null,
      sql_digest: firstSubject.sql_digest || null,
      threshold: policyArtifact.threshold || 0,
      allow_count: policyArtifact.allow_count || 0,
      total_witnesses: policyArtifact.total_witnesses || 0,
      decision_digests: (policyArtifact.decisions || []).map((decision) => digestValue({ subject: decision.subject, signature: decision.signature }))
    };
  }
  return {
    is_quorum: false,
    version: policyArtifact.version,
    policy_id: policyArtifact.policy_id,
    policy_epoch_id: policyArtifact.policy_epoch_id,
    policy_bundle_digest: policyArtifact.policy_bundle_digest,
    decision: policyArtifact.decision,
    reasons: policyArtifact.reasons || [],
    rule_results: policyArtifact.rule_results || [],
    request_digest: policyArtifact.request_digest || null,
    sql_digest: policyArtifact.sql?.sql_digest || null
  };
}

function kojimemPolicyEvidence(policyArtifact) {
  if (!policyArtifact) {
    return {};
  }
  if (policyArtifact.version === KOJIMEM_POLICY_QUORUM_VERSION) {
    const firstSubject = policyArtifact.decisions?.[0]?.subject || {};
    const reasons = policyArtifact.deny_reasons || [...new Set((policyArtifact.decisions || []).flatMap((decision) => decision.subject?.reasons || []))];
    return {
      is_quorum: true,
      version: policyArtifact.version,
      policy_id: policyArtifact.policy_id,
      policy_epoch_id: policyArtifact.policy_epoch_id,
      policy_bundle_digest: policyArtifact.policy_bundle_digest,
      decision: policyArtifact.decision,
      reasons,
      rule_results: firstSubject.rule_results || [],
      request_digest: policyArtifact.request_digest || firstSubject.request_digest || null,
      threshold: policyArtifact.threshold || 0,
      allow_count: policyArtifact.allow_count || 0,
      total_witnesses: policyArtifact.total_witnesses || 0,
      decision_digests: (policyArtifact.decisions || []).map((decision) => digestValue({ subject: decision.subject, signature: decision.signature }))
    };
  }
  return {
    is_quorum: false,
    version: policyArtifact.version,
    policy_id: policyArtifact.policy_id,
    policy_epoch_id: policyArtifact.policy_epoch_id,
    policy_bundle_digest: policyArtifact.policy_bundle_digest,
    decision: policyArtifact.decision,
    reasons: policyArtifact.reasons || [],
    rule_results: policyArtifact.rule_results || [],
    request_digest: policyArtifact.request_digest || null
  };
}

function sameArray(left = [], right = []) {
  return JSON.stringify(left || []) === JSON.stringify(right || []);
}

function isDigestOnlySupabaseResultMetadata(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  if (hasAnyOwnKey(value, ["text", "json", "rows", "data", "content", "raw_result", "response", "tool_result", "tool_result_payload", "payload"])) {
    return false;
  }
  if (value.version) {
    return value.version === SUPABASE_RESULT_SUMMARY_VERSION
      && value.evidence_mode === "digest-only"
      && Boolean(value.result_digest)
      && Boolean(value.result_text_digest)
      && typeof value.result_bytes === "number";
  }
  return Object.keys(value).every((key) => key === "upstream_error");
}

function hasRawSupabasePayload(bundle) {
  const certificate = bundle.certificate || {};
  const resultMetadata = bundle.supabase_result_metadata || {};
  return hasAnyOwnKey(bundle, ["tool_result", "tool_result_payload", "raw_result", "upstream_result"])
    || hasAnyOwnKey(certificate, ["tool_result", "tool_result_payload", "raw_result", "upstream_result"])
    || certificate.result_preview != null
    || hasAnyOwnKey(resultMetadata, ["text", "json", "rows", "data", "content", "raw_result", "response", "payload"]);
}

function hasAnyOwnKey(value, keys) {
  return Boolean(value && typeof value === "object" && keys.some((key) => Object.prototype.hasOwnProperty.call(value, key)));
}

function verifyOperatorIdentityBinding(checks, bundle, certificate) {
  const binding = certificate.operator_identity;
  if (!binding) {
    warn(checks, "operator_identity.present", "Certificate does not include an explicit operator_identity binding; relying on legacy admission/operator_registry bindings.");
    return;
  }

  add(checks, "operator_identity.version", binding.version === OPERATOR_IDENTITY_BINDING_VERSION, {
    expected: OPERATOR_IDENTITY_BINDING_VERSION,
    actual: binding.version || null
  });

  const operatorRegistry = bundle.operator_registry || null;
  const operatorRecord = operatorRegistry?.operator_record || null;
  const registryTrustAnchor = operatorRegistry?.registry_trust_anchor || null;
  const admissionManifest = bundle.admission_manifest || null;

  add(checks, "operator_identity.registry_record_present", Boolean(operatorRecord && registryTrustAnchor), {
    operator_record: Boolean(operatorRecord),
    registry_trust_anchor: Boolean(registryTrustAnchor)
  });

  if (admissionManifest) {
    const admissionVerification = verifyOperatorAdmissionManifest(admissionManifest, {
      operatorRegistryBinding: operatorRegistry,
      requireRegistry: true
    });
    add(checks, "operator_identity.admission_signature", admissionVerification.ok, { errors: admissionVerification.errors });
    add(checks, "operator_identity.admission_manifest_digest", binding.admission_manifest_digest === admissionVerification.signed_manifest_digest && certificate.admission?.admission_manifest_digest === admissionVerification.signed_manifest_digest, {
      expected: binding.admission_manifest_digest,
      certificate_admission: certificate.admission?.admission_manifest_digest || null,
      actual: admissionVerification.signed_manifest_digest
    });
    add(checks, "operator_identity.operator_id", binding.operator_id === admissionVerification.operator_id, {
      expected: admissionVerification.operator_id,
      actual: binding.operator_id || null
    });
    add(checks, "operator_identity.tenant_id", binding.tenant_id === admissionVerification.tenant_id, {
      expected: admissionVerification.tenant_id,
      actual: binding.tenant_id || null
    });
    add(checks, "operator_identity.operator_key", binding.operator_key_id === admissionVerification.operator_key_id && binding.operator_key_id === certificate.admission?.operator_key_id, {
      expected: admissionVerification.operator_key_id,
      certificate_admission: certificate.admission?.operator_key_id || null,
      actual: binding.operator_key_id || null
    });
  } else {
    add(checks, "operator_identity.admission_manifest_present", false, {});
  }

  if (!operatorRecord) {
    return;
  }

  const operatorRecordDigest = digestValue(operatorRecord);
  add(checks, "operator_identity.registry_record_digest", binding.operator_registry_record_digest === operatorRecordDigest && certificate.admission?.operator_registry_record_digest === operatorRecordDigest, {
    expected: binding.operator_registry_record_digest,
    certificate_admission: certificate.admission?.operator_registry_record_digest || null,
    actual: operatorRecordDigest
  });
  add(checks, "operator_identity.registry_authority", binding.registry_authority_key_id === registryTrustAnchor?.key_id, {
    expected: registryTrustAnchor?.key_id || null,
    actual: binding.registry_authority_key_id || null
  });
  add(checks, "operator_identity.registry_url", binding.operator_registry_url === operatorRegistry?.operator_record_url, {
    expected: operatorRegistry?.operator_record_url || null,
    actual: binding.operator_registry_url || null
  });
  add(checks, "operator_identity.workflow_authorization", operatorRecord.authorized_workflows?.includes(binding.workflow_id), {
    workflow_id: binding.workflow_id || null,
    authorized_workflows: operatorRecord.authorized_workflows || []
  });
  add(checks, "operator_identity.tool_authorization", operatorRecord.authorized_tools?.includes(binding.tool_id), {
    tool_id: binding.tool_id || null,
    authorized_tools: operatorRecord.authorized_tools || []
  });
  add(checks, "operator_identity.policy_authorization", operatorRecord.authorized_policy_hashes?.includes(binding.policy_hash), {
    policy_hash: binding.policy_hash || null,
    authorized_policy_hashes: operatorRecord.authorized_policy_hashes || []
  });
  const timeErrors = operatorRecordTimeErrors(operatorRecord, binding.admission_signed_at || certificate.issued_at);
  add(checks, "operator_identity.status_at_action_time", binding.status_at_action_time === "active" && operatorRecord.status === "active" && timeErrors.length === 0, {
    binding_status: binding.status_at_action_time || null,
    record_status: operatorRecord.status || null,
    errors: timeErrors
  });
}

function operatorRecordTimeErrors(record, signingTime) {
  const errors = [];
  const signedAt = Date.parse(signingTime || "");
  if (!Number.isFinite(signedAt)) {
    return ["operator signing time missing or invalid"];
  }
  if (record.valid_from && signedAt < Date.parse(record.valid_from)) {
    errors.push("operator key was not valid yet at signing time");
  }
  if (record.valid_until && signedAt > Date.parse(record.valid_until)) {
    errors.push("operator key expired before signing time");
  }
  return errors;
}

async function verifyGatewayAttestation(checks, bundle) {
  const gateway = bundle.certificate?.tinfoil_attestation?.gateway;
  const artifact = bundle.gateway_attestation;
  add(checks, "gateway_attestation.present", Boolean(gateway?.attestation_digest), {
    attestation_digest: gateway?.attestation_digest || null
  });
  add(checks, "gateway_attestation.artifact_present", Boolean(artifact?.document), {});
  if (!gateway?.attestation_digest || !artifact?.document) {
    return;
  }
  const documentDigest = digestValue(artifact.document);
  const tinfoilDocumentHash = await hashAttestationDocument(artifact.document);
  add(checks, "gateway_attestation.document_digest", documentDigest === gateway.attestation_digest, {
    expected: gateway.attestation_digest,
    actual: documentDigest
  });
  add(checks, "gateway_attestation.tinfoil_document_hash", tinfoilDocumentHash === gateway.observed_attestation?.tinfoil_document_hash, {
    expected: gateway.observed_attestation?.tinfoil_document_hash || null,
    actual: tinfoilDocumentHash
  });
  add(checks, "gateway_attestation.format_body", Boolean(artifact.document.format && artifact.document.body), {
    format: artifact.document.format || null,
    body_length: artifact.document.body?.length || 0
  });
  await verifyOfficialTinfoilBundle(checks, "gateway_attestation.official_verifier", gateway, artifact.attestation_bundle);
}

function verifyL1Attestations(checks, bundle) {
  const l1 = bundle.certificate?.tinfoil_attestation?.l1_witnesses || [];
  const observed = bundle.l1_witness_attestations?.witnesses || [];
  if (l1.length === 0) {
    add(checks, "l1_attestation.present", false, {});
    return [];
  }
  add(checks, "l1_attestation.static_present", l1.every((item) => Boolean(item.attestation_digest)), {
    witness_count: l1.length
  });
  if (observed.length === 0) {
    warn(checks, "l1_attestation.observed_artifact_present", "No observed L1 attestation documents were included; static L1 attestation refs are present.");
    return [];
  }
  return observed.map(async (item) => {
    const label = item.runtime?.witness_id || item.runtime?.container_name || "unknown";
    const digest = item.document ? digestValue(item.document) : null;
    const tinfoilDocumentHash = item.document ? await hashAttestationDocument(item.document) : null;
    add(checks, `l1_attestation.${label}.document_digest`, digest === item.runtime?.observed_attestation?.attestation_document_digest, {
      expected: item.runtime?.observed_attestation?.attestation_document_digest || null,
      actual: digest
    });
    add(checks, `l1_attestation.${label}.tinfoil_document_hash`, tinfoilDocumentHash === item.runtime?.observed_attestation?.tinfoil_document_hash, {
      expected: item.runtime?.observed_attestation?.tinfoil_document_hash || null,
      actual: tinfoilDocumentHash
    });
    await verifyOfficialTinfoilBundle(checks, `l1_attestation.${label}.official_verifier`, item.runtime, item.attestation_bundle);
  });
}

async function verifyOfficialTinfoilBundle(checks, name, runtime, attestationBundle) {
  if (!runtime?.config_repo) {
    add(checks, name, false, { error: "runtime config_repo missing" });
    return;
  }
  if (!attestationBundle) {
    add(checks, name, false, { error: "attestation_bundle artifact missing" });
    return;
  }
  try {
    const verifier = new Verifier({ configRepo: runtime.config_repo });
    const attestation = await verifier.verifyBundle(attestationBundle);
    const verificationDocument = verifier.getVerificationDocument();
    add(checks, name, true, {
      config_repo: runtime.config_repo,
      release_digest: attestationBundle.digest,
      measurement_type: attestation.measurement?.type,
      measurement_registers: attestation.measurement?.registers,
      tls_public_key_fingerprint: attestation.tlsPublicKeyFingerprint || null,
      hpke_public_key: attestation.hpkePublicKey || null,
      verification_document: verificationDocument || null
    });
  } catch (error) {
    add(checks, name, false, {
      config_repo: runtime.config_repo,
      error: error.message
    });
  }
}

function add(checks, name, ok, details) {
  checks.push({ name, ok: Boolean(ok), severity: ok ? "pass" : "fail", ...details });
}

function warn(checks, name, message) {
  checks.push({ name, ok: true, severity: "warn", message });
}

function result({ sourceUrl, certificate, evidence = null, checks }) {
  const failed = checks.filter((check) => check.severity === "fail");
  const warnings = checks.filter((check) => check.severity === "warn");
  return {
    ok: failed.length === 0,
    source_url: sourceUrl,
    certificate,
    evidence,
    summary: {
      pass: checks.filter((check) => check.severity === "pass").length,
      warn: warnings.length,
      fail: failed.length
    },
    checks
  };
}

function withoutDigest(certificate) {
  const { certificate_digest, ...rest } = certificate;
  return rest;
}

async function getJson(url) {
  const response = await fetch(url);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}: ${text}`);
  }
  return JSON.parse(text);
}

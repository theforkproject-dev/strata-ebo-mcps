import {
  digestValue,
  verifyCheckpoint,
  verifySession,
  verifyWitnessAuthority,
  verifyWitnessRegistryEpoch,
  witnessRegistryEpochDigest
} from "../strata/primitives.js";
import { policyBundleDigest, verifyPolicyQuorumAuthority } from "../policy/email-policy.js";
import { SUPABASE_POLICY_BUNDLE_VERSION, supabasePolicyBundleDigest } from "../policy/supabase-policy.js";
import {
  SUPABASE_ACTION_CERTIFICATE_VERSION,
  SUPABASE_CONNECTOR_MANIFEST_VERSION,
  SUPABASE_POLICY_DECISION_VERSION
} from "../supabase/canonical.js";
import { verifyOperatorRegistryRecord } from "../registry/email-registry.js";
import { verifyOperatorAdmissionManifest } from "../admission/operator-manifest.js";
import { Verifier, hashAttestationDocument } from "@tinfoilsh/verifier";

const OPERATOR_IDENTITY_BINDING_VERSION = "strata.operator_identity_binding.v1";
const EMAIL_CERTIFICATE_BUNDLE_VERSION = "strata.email.certificate_bundle.v1";
const SUPABASE_CERTIFICATE_BUNDLE_VERSION = "strata.supabase.certificate_bundle.v1";
const SUPABASE_POLICY_DENIAL_CERTIFICATE_VERSION = "strata.supabase.policy_denial_certificate.v1";
const SUPABASE_REQUEST_VERSION = "strata.supabase.request.v1";
const SUPABASE_RESULT_SUMMARY_VERSION = "strata.supabase.result_summary.v1";

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
  if (bundle?.version === SUPABASE_CERTIFICATE_BUNDLE_VERSION || String(bundle?.certificate?.version || "").startsWith("strata.supabase.")) {
    return verifySupabaseCertificateBundle(bundle, { sourceUrl });
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
    add(checks, "supabase.request.digest", requestDigest === certificate.request?.request_digest && requestDigest === policyDecision?.request_digest, {
      certificate_request_digest: certificate.request?.request_digest || null,
      policy_request_digest: policyDecision?.request_digest || null,
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
    add(checks, "supabase.policy_bundle.digest", policyDigest === certificate.policy?.policy_bundle_digest && policyDigest === policyDecision?.policy_bundle_digest, {
      certificate_policy_bundle_digest: certificate.policy?.policy_bundle_digest || null,
      policy_decision_policy_bundle_digest: policyDecision?.policy_bundle_digest || null,
      actual: policyDigest
    });
    add(checks, "supabase.policy_bundle.identity", policyBundle.policy_id === certificate.policy?.policy_id && policyBundle.epoch_id === certificate.policy?.policy_epoch_id, {
      policy_id: policyBundle.policy_id || null,
      certificate_policy_id: certificate.policy?.policy_id || null,
      policy_epoch_id: policyBundle.epoch_id || null,
      certificate_policy_epoch_id: certificate.policy?.policy_epoch_id || null
    });
  }

  add(checks, "supabase.policy_decision.present", Boolean(policyDecision), {});
  if (policyDecision) {
    const failedRules = (policyDecision.rule_results || []).filter((item) => item.pass !== true);
    add(checks, "supabase.policy_decision.version", policyDecision.version === SUPABASE_POLICY_DECISION_VERSION, {
      expected: SUPABASE_POLICY_DECISION_VERSION,
      actual: policyDecision.version || null
    });
    add(checks, "supabase.policy_decision.result", policyDecision.decision === certificate.policy?.decision && sameArray(policyDecision.reasons || [], certificate.policy?.reasons || []), {
      policy_decision: policyDecision.decision || null,
      certificate_decision: certificate.policy?.decision || null,
      policy_reasons: policyDecision.reasons || [],
      certificate_reasons: certificate.policy?.reasons || []
    });
    add(checks, "supabase.policy_decision.rule_consistency", policyDecision.decision === "allow" ? failedRules.length === 0 : failedRules.length > 0, {
      decision: policyDecision.decision || null,
      failed_rules: failedRules.map((item) => item.rule)
    });
    const expectedSqlDigest = policyDecision.sql?.sql_digest || null;
    add(checks, "supabase.policy_decision.sql_digest", (certificate.request?.sql_digest || null) === expectedSqlDigest, {
      expected: expectedSqlDigest,
      actual: certificate.request?.sql_digest || null
    });
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
  add(checks, "supabase.denied_consistency", certificate.denied === (policyDecision?.decision === "deny"), {
    certificate_denied: certificate.denied === true,
    policy_decision: policyDecision?.decision || null
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

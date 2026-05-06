import {
  digestValue,
  verifyCheckpoint,
  verifySession,
  verifyWitnessAuthority,
  verifyWitnessRegistryEpoch,
  witnessRegistryEpochDigest
} from "../strata/primitives.js";
import { policyBundleDigest, verifyPolicyQuorumAuthority } from "../policy/email-policy.js";
import { verifyOperatorRegistryRecord } from "../registry/email-registry.js";
import { Verifier, hashAttestationDocument } from "@tinfoilsh/verifier";

export async function verifyCertificateBundleUrl(bundleUrl) {
  const bundle = await getJson(bundleUrl);
  return verifyCertificateBundle(bundle, { sourceUrl: bundleUrl });
}

export async function verifyCertificateBundle(bundle, { sourceUrl = "" } = {}) {
  const checks = [];
  const certificate = bundle.certificate;
  const registryArtifact = bundle.registry_epoch;
  const registryEpoch = registryArtifact?.registry_epoch;
  const registryTrustAnchor = registryArtifact?.registry_trust_anchor;
  const policyQuorum = bundle.policy_decision;
  const policyBundle = bundle.policy_bundle;
  const keyring = bundle.keyring || {};
  const transparencyLog = bundle.transparency_log || [];

  add(checks, "bundle.version", bundle.version === "strata.email.certificate_bundle.v1", { actual: bundle.version });
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
    add(checks, "operator_registry.digest", digestValue(bundle.operator_registry.operator_record) === certificate.admission?.operator_registry_record_digest, {
      expected: certificate.admission?.operator_registry_record_digest,
      actual: digestValue(bundle.operator_registry.operator_record)
    });
  } else {
    add(checks, "operator_registry.artifact_present", false, {});
  }

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
      policy: certificate.policy,
      proof: certificate.proof
    },
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

function result({ sourceUrl, certificate, checks }) {
  const failed = checks.filter((check) => check.severity === "fail");
  const warnings = checks.filter((check) => check.severity === "warn");
  return {
    ok: failed.length === 0,
    source_url: sourceUrl,
    certificate,
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

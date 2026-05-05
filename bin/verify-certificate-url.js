#!/usr/bin/env node
import {
  digestValue,
  verifyCheckpoint,
  verifySession,
  verifyWitnessAuthority,
  verifyWitnessRegistryEpoch,
  witnessRegistryEpochDigest
} from "../src/strata/primitives.js";
import { policyBundleDigest, verifyPolicyQuorumAuthority } from "../src/policy/email-policy.js";
import { verifyOperatorRegistryRecord } from "../src/registry/email-registry.js";

const bundleUrl = process.argv[2];
if (!bundleUrl) {
  console.error("Usage: node bin/verify-certificate-url.js <bundle-url>");
  process.exit(2);
}

try {
  const bundle = await getJson(bundleUrl);
  const report = verifyBundle(bundle, bundleUrl);
  console.log(JSON.stringify(report, null, 2));
  process.exit(report.ok ? 0 : 1);
} catch (error) {
  console.error(JSON.stringify({ ok: false, error: error.message }, null, 2));
  process.exit(1);
}

function verifyBundle(bundle, sourceUrl) {
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

  verifyGatewayAttestation(checks, bundle);
  verifyL1Attestations(checks, bundle);

  return result({
    sourceUrl,
    certificate: {
      url: certificate.certificate_url,
      digest: certificate.certificate_digest,
      issued_at: certificate.issued_at,
      provider: certificate.provider?.provider,
      provider_message_id: certificate.provider?.provider_message_id
    },
    checks
  });
}

function verifyGatewayAttestation(checks, bundle) {
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
  add(checks, "gateway_attestation.document_digest", documentDigest === gateway.attestation_digest, {
    expected: gateway.attestation_digest,
    actual: documentDigest
  });
  add(checks, "gateway_attestation.format_body", Boolean(artifact.document.format && artifact.document.body), {
    format: artifact.document.format || null,
    body_length: artifact.document.body?.length || 0
  });
}

function verifyL1Attestations(checks, bundle) {
  const l1 = bundle.certificate?.tinfoil_attestation?.l1_witnesses || [];
  const observed = bundle.l1_witness_attestations?.witnesses || [];
  if (l1.length === 0) {
    add(checks, "l1_attestation.present", false, {});
    return;
  }
  add(checks, "l1_attestation.static_present", l1.every((item) => Boolean(item.attestation_digest)), {
    witness_count: l1.length
  });
  if (observed.length === 0) {
    warn(checks, "l1_attestation.observed_artifact_present", "No observed L1 attestation documents were included; static L1 attestation refs are present.");
    return;
  }
  for (const item of observed) {
    const digest = item.document ? digestValue(item.document) : null;
    add(checks, `l1_attestation.${item.runtime?.witness_id || item.runtime?.container_name || "unknown"}.document_digest`, digest === item.runtime?.observed_attestation?.attestation_document_digest, {
      expected: item.runtime?.observed_attestation?.attestation_document_digest || null,
      actual: digest
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

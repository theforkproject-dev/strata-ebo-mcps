import {
  admissionManifestDigest,
  canonicalize,
  loadOrCreateEd25519Signer,
  signEd25519,
  verifyEd25519
} from "../strata/primitives.js";

export const OPERATOR_ADMISSION_SIGNATURE_VERSION = "strata.operator_admission_signature.v1";
export const OPERATOR_ADMISSION_SIGNATURE_SUBJECT_VERSION = "strata.operator_admission_signature_subject.v1";

export function loadOperatorAdmissionSigner(config) {
  return loadOrCreateEd25519Signer({
    keyFile: config.operator.admissionKeyJson || config.operator.admissionPrivateKeyPem ? null : config.operator.admissionKeyFile,
    keyId: config.operator.admissionKeyId,
    keyJson: config.operator.admissionKeyJson,
    privateKeyPem: config.operator.admissionPrivateKeyPem,
    publicKeyPem: config.operator.admissionPublicKeyPem
  });
}

export function attachOperatorSignature(manifest, { signer, publicKeyPem, operatorId, tenantId, issuedAt = new Date().toISOString() }) {
  const unsignedManifest = withoutOperatorSignature(manifest);
  const subject = operatorAdmissionSubject(unsignedManifest, {
    operatorId,
    tenantId,
    keyId: signer.keyId,
    issuedAt
  });
  return {
    ...unsignedManifest,
    operator_signature: {
      version: OPERATOR_ADMISSION_SIGNATURE_VERSION,
      operator_id: operatorId,
      tenant_id: tenantId,
      key_id: signer.keyId,
      public_key_pem: publicKeyPem,
      subject,
      signature: {
        key_id: signer.keyId,
        algorithm: "Ed25519",
        signature: signEd25519(canonicalize(subject), signer.privateKey)
      }
    }
  };
}

export function verifyOperatorAdmissionManifest(manifest, { operatorRegistryBinding = null, requireRegistry = false } = {}) {
  const errors = [];
  const operatorSignature = manifest?.operator_signature;
  if (!operatorSignature) {
    return {
      ok: false,
      errors: ["operator admission signature missing"],
      manifest_digest: manifest ? admissionManifestDigest(manifest) : null
    };
  }

  const operatorRecord = operatorRegistryBinding?.operator_record || null;
  if (requireRegistry && !operatorRecord) {
    errors.push("operator registry record missing");
  }
  if (operatorRegistryBinding?.verification && !operatorRegistryBinding.verification.ok) {
    errors.push(...operatorRegistryBinding.verification.errors.map((error) => `operator registry: ${error}`));
  }
  if (operatorRecord) {
    if (operatorRecord.operator_id !== operatorSignature.operator_id) {
      errors.push(`operator registry operator_id mismatch: manifest=${operatorSignature.operator_id} registry=${operatorRecord.operator_id}`);
    }
    if (operatorRecord.tenant_id !== operatorSignature.tenant_id) {
      errors.push(`operator registry tenant_id mismatch: manifest=${operatorSignature.tenant_id} registry=${operatorRecord.tenant_id}`);
    }
    if (operatorRecord.key_id !== operatorSignature.key_id) {
      errors.push(`operator registry key_id mismatch: manifest=${operatorSignature.key_id} registry=${operatorRecord.key_id}`);
    }
    if (operatorRecord.public_key_pem !== operatorSignature.public_key_pem) {
      errors.push("operator registry public key does not match manifest embedded key");
    }
    if (!operatorRecord.authorized_policy_hashes?.includes(manifest.policy_hash)) {
      errors.push(`operator registry key is not authorized for policy ${manifest.policy_hash}`);
    }
    if (!operatorRecord.authorized_workflows?.includes("email.send")) {
      errors.push("operator registry key is not authorized for workflow email.send");
    }
    if (operatorRecord.status !== "active") {
      errors.push(`operator registry key status is ${operatorRecord.status}`);
    }
    errors.push(...operatorRecordTimeErrors(operatorRecord, operatorSignature.subject?.issued_at));
  }

  const unsignedManifest = withoutOperatorSignature(manifest);
  const expectedSubject = operatorAdmissionSubject(unsignedManifest, {
    operatorId: operatorSignature.operator_id,
    tenantId: operatorSignature.tenant_id,
    keyId: operatorSignature.key_id,
    issuedAt: operatorSignature.subject?.issued_at
  });

  if (JSON.stringify(operatorSignature.subject) !== JSON.stringify(expectedSubject)) {
    errors.push("operator admission signature subject mismatch");
  }
  if (operatorSignature.signature?.key_id !== operatorSignature.key_id) {
    errors.push("operator admission signature key_id mismatch");
  }
  if (!operatorSignature.public_key_pem) {
    errors.push("operator admission public key missing");
  } else if (!operatorSignature.signature?.signature) {
    errors.push("operator admission signature missing");
  } else if (!verifyEd25519(canonicalize(operatorSignature.subject), operatorSignature.signature.signature, operatorRecord?.public_key_pem || operatorSignature.public_key_pem)) {
    errors.push("operator admission signature verification failed");
  }

  return {
    ok: errors.length === 0,
    errors,
    tenant_id: operatorSignature.tenant_id,
    operator_id: operatorSignature.operator_id,
    operator_key_id: operatorSignature.key_id,
    manifest_id: manifest.manifest_id,
    governance_id: manifest.governance_id,
    policy_hash: manifest.policy_hash,
    policy_bundle_url: manifest.policy_bundle_url || null,
    unsigned_manifest_digest: admissionManifestDigest(unsignedManifest),
    signed_manifest_digest: admissionManifestDigest(manifest),
    signed_at: operatorSignature.subject?.issued_at || null,
    registry_authorized: Boolean(operatorRecord) && !errors.some((error) => error.startsWith("operator registry")),
    operator_registry_url: operatorRegistryBinding?.operator_record_url || null,
    operator_registry_record_digest: operatorRegistryBinding?.operator_record_digest || null,
    operator_registry_authority_key_id: operatorRegistryBinding?.registry_trust_anchor?.key_id || null
  };
}

export function optionalOperatorAdmissionVerification(manifest, { required = false, operatorRegistryBinding = null, requireRegistry = false } = {}) {
  if (!manifest) {
    return { ok: !required, skipped: !required, errors: required ? ["operator admission manifest artifact missing"] : [] };
  }
  return verifyOperatorAdmissionManifest(manifest, { operatorRegistryBinding, requireRegistry });
}

export function operatorAdmissionCertificateBinding(manifest, { operatorRegistryBinding = null } = {}) {
  const verification = verifyOperatorAdmissionManifest(manifest, { operatorRegistryBinding });
  return {
    tenant_id: verification.tenant_id,
    operator_id: verification.operator_id,
    operator_key_id: verification.operator_key_id,
    manifest_id: verification.manifest_id,
    governance_id: verification.governance_id,
    admission_manifest_digest: verification.signed_manifest_digest,
    unsigned_manifest_digest: verification.unsigned_manifest_digest,
    policy_hash: verification.policy_hash,
    policy_bundle_url: verification.policy_bundle_url,
    operator_registry_url: verification.operator_registry_url,
    operator_registry_record_digest: verification.operator_registry_record_digest,
    operator_registry_authority_key_id: verification.operator_registry_authority_key_id,
    registry_authorized: verification.registry_authorized,
    signature_version: OPERATOR_ADMISSION_SIGNATURE_VERSION,
    signature_verified: verification.ok
  };
}

function operatorRecordTimeErrors(record, signingTime) {
  const errors = [];
  if (!signingTime) {
    errors.push("operator registry signing time missing");
    return errors;
  }
  const signedAt = Date.parse(signingTime);
  if (record.valid_from && signedAt < Date.parse(record.valid_from)) {
    errors.push("operator registry key was not valid at signing time");
  }
  if (record.valid_until && signedAt > Date.parse(record.valid_until)) {
    errors.push("operator registry key expired before signing time");
  }
  return errors;
}

export function withoutOperatorSignature(manifest) {
  const { operator_signature, ...unsignedManifest } = manifest || {};
  return unsignedManifest;
}

function operatorAdmissionSubject(manifest, { operatorId, tenantId, keyId, issuedAt }) {
  return {
    version: OPERATOR_ADMISSION_SIGNATURE_SUBJECT_VERSION,
    operator_id: operatorId,
    tenant_id: tenantId,
    key_id: keyId,
    manifest_id: manifest.manifest_id,
    governance_id: manifest.governance_id,
    policy_hash: manifest.policy_hash,
    policy_bundle_url: manifest.policy_bundle_url || null,
    unsigned_manifest_digest: admissionManifestDigest(manifest),
    issued_at: issuedAt
  };
}

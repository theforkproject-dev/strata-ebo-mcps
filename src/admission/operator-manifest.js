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
    keyFile: config.operator.admissionKeyFile,
    keyId: config.operator.admissionKeyId
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

export function verifyOperatorAdmissionManifest(manifest) {
  const errors = [];
  const operatorSignature = manifest?.operator_signature;
  if (!operatorSignature) {
    return {
      ok: false,
      errors: ["operator admission signature missing"],
      manifest_digest: manifest ? admissionManifestDigest(manifest) : null
    };
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
  } else if (!verifyEd25519(canonicalize(operatorSignature.subject), operatorSignature.signature.signature, operatorSignature.public_key_pem)) {
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
    signed_at: operatorSignature.subject?.issued_at || null
  };
}

export function optionalOperatorAdmissionVerification(manifest, { required = false } = {}) {
  if (!manifest) {
    return { ok: !required, skipped: !required, errors: required ? ["operator admission manifest artifact missing"] : [] };
  }
  return verifyOperatorAdmissionManifest(manifest);
}

export function operatorAdmissionCertificateBinding(manifest) {
  const verification = verifyOperatorAdmissionManifest(manifest);
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
    signature_version: OPERATOR_ADMISSION_SIGNATURE_VERSION,
    signature_verified: verification.ok
  };
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

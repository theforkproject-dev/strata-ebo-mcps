import {
  WITNESS_REGISTRY_EPOCH_VERSION,
  canonicalize,
  digestValue,
  loadOrCreateEd25519Signer,
  signEd25519,
  verifyEd25519,
  signWitnessRegistryEpoch,
  verifyWitnessRegistryEpoch,
  witnessRegistryEpochDigest
} from "../strata/primitives.js";
import {
  EMAIL_POLICY_POINTER_VERSION,
  defaultEmailPolicyBundle,
  policyBundleDigest,
  policyBundleMetadata
} from "../policy/email-policy.js";

export const REGISTRY_ID = "strata-email-demo-registry";
export const REGISTRY_EPOCH_ID = process.env.EMAIL_REGISTRY_EPOCH_ID || "email-demo-epoch-001";
export const REGISTRY_VALID_FROM = "2026-04-28T00:00:00.000Z";
export const OPERATOR_REGISTRY_RECORD_VERSION = "strata.operator_registry_record.v1";

export function loadRegistrySigner({ keyFile = "artifacts/registry/registry-authority.key.json", keyId = "registry-authority:email-demo" } = {}) {
  return loadOrCreateEd25519Signer({ keyFile, keyId });
}

export async function buildEmailRegistryEpoch({ mechanicalWitnesses, policyWitnesses, signer, policyBundle = defaultEmailPolicyBundle(), policyUrl = "", fetchImpl = fetch }) {
  const policyHash = policyBundleDigest(policyBundle);
  const mechanical = await Promise.all(mechanicalWitnesses.map((witness) => witnessEntry({ witness, tier: "mechanical", policyHash, fetchImpl })));
  const policy = await Promise.all(policyWitnesses.map((witness) => witnessEntry({ witness, tier: "policy", policyHash, fetchImpl })));
  const epoch = {
    version: WITNESS_REGISTRY_EPOCH_VERSION,
    registry_id: REGISTRY_ID,
    epoch_id: REGISTRY_EPOCH_ID,
    valid_from: REGISTRY_VALID_FROM,
    valid_until: null,
    workflow_id: "email.send",
    policy_bundle_digest: policyHash,
    policy_bundle_url: policyUrl || null,
    status_semantics: {
      deprecated: true,
      expired: true,
      revoked: true,
      compromised: true
    },
    witnesses: [...mechanical, ...policy],
    signatures: []
  };
  const signed = signWitnessRegistryEpoch(epoch, signer);
  return {
    epoch: signed,
    epoch_digest: witnessRegistryEpochDigest(signed),
    trust_anchor: {
      key_id: signer.keyId,
      public_key_pem: signer.publicKeyPem
    },
    verification: verifyWitnessRegistryEpoch(signed, { [signer.keyId]: signer.publicKeyPem })
  };
}

export function buildEmailPolicyPointer({ policyBundle = defaultEmailPolicyBundle(), policyUrl, signer }) {
  const pointer = {
    version: EMAIL_POLICY_POINTER_VERSION,
    registry_id: REGISTRY_ID,
    pointer_id: "current",
    valid_from: REGISTRY_VALID_FROM,
    active_policy: policyBundleMetadata(policyBundle, policyUrl)
  };
  return {
    ...pointer,
    signature: {
      key_id: signer.keyId,
      algorithm: "Ed25519",
      signature: signEd25519(canonicalize(pointer), signer.privateKey)
    }
  };
}

export function buildOperatorRegistryRecord({
  operatorId,
  tenantId,
  keyId,
  publicKeyPem,
  signer,
  policyBundle = defaultEmailPolicyBundle(),
  policyUrl = ""
}) {
  const policyHash = policyBundleDigest(policyBundle);
  const record = {
    version: OPERATOR_REGISTRY_RECORD_VERSION,
    registry_id: REGISTRY_ID,
    operator_id: operatorId,
    tenant_id: tenantId,
    key_id: keyId,
    public_key_pem: publicKeyPem,
    authorized_workflows: ["email.send"],
    authorized_tools: ["email_send_verified"],
    authorized_policy_hashes: [policyHash],
    policy_bundle_url: policyUrl || null,
    valid_from: REGISTRY_VALID_FROM,
    valid_until: null,
    status: "active",
    status_events: [],
    signatures: []
  };
  return {
    ...record,
    signatures: [{
      key_id: signer.keyId,
      algorithm: "Ed25519",
      signature: signEd25519(canonicalize(record), signer.privateKey)
    }]
  };
}

export function verifyOperatorRegistryRecord(record, trustAnchors = {}) {
  const errors = [];
  if (!record || record.version !== OPERATOR_REGISTRY_RECORD_VERSION) {
    return { ok: false, errors: ["invalid operator registry record version"] };
  }
  if (!record.operator_id) {
    errors.push("operator_id missing");
  }
  if (!record.tenant_id) {
    errors.push("tenant_id missing");
  }
  if (!record.key_id) {
    errors.push("operator key_id missing");
  }
  if (!record.public_key_pem) {
    errors.push("operator public_key_pem missing");
  }
  if (record.status !== "active") {
    errors.push(`operator key status is ${record.status}`);
  }
  const unsignedRecord = { ...record, signatures: [] };
  const signatures = record.signatures || [];
  if (signatures.length === 0) {
    errors.push("operator registry record signature missing");
  }
  const verifiedSignatures = [];
  for (const signature of signatures) {
    if (!signature?.signature) {
      errors.push("operator registry signature value missing");
      continue;
    }
    const publicKey = trustAnchors[signature.key_id];
    if (!publicKey) {
      errors.push(`operator registry signature key ${signature.key_id} is not trusted`);
      continue;
    }
    if (!verifyEd25519(canonicalize(unsignedRecord), signature.signature, publicKey)) {
      errors.push(`operator registry signature ${signature.key_id} verification failed`);
      continue;
    }
    verifiedSignatures.push(signature.key_id);
  }
  return {
    ok: errors.length === 0,
    errors,
    operator_record_digest: digestValue(record),
    verified_signatures: verifiedSignatures
  };
}

export async function fetchRegistryBinding(registryUrl, options = {}, fetchImpl = fetch) {
  if (!registryUrl) {
    return null;
  }
  const base = registryUrl.replace(/\/$/, "");
  const [epochResponse, publicKeyResponse] = await Promise.all([
    fetchImpl(`${base}/registry/current`),
    fetchImpl(`${base}/registry/public-key`)
  ]);
  const epoch = await epochResponse.json();
  const trustAnchor = await publicKeyResponse.json();
  if (!epochResponse.ok) {
    throw new Error(epoch.error || `registry current returned ${epochResponse.status}`);
  }
  if (!publicKeyResponse.ok) {
    throw new Error(trustAnchor.error || `registry public key returned ${publicKeyResponse.status}`);
  }
  const trustedAnchor = pinnedTrustAnchor(options) || trustAnchor;
  verifyFetchedTrustAnchor(trustAnchor, trustedAnchor);
  const verification = verifyWitnessRegistryEpoch(epoch, { [trustedAnchor.key_id]: trustedAnchor.public_key_pem });
  const epochDigest = witnessRegistryEpochDigest(epoch);
  verifyExpectedDigest("registry epoch", epochDigest, options.expectedEpochDigest);
  return {
    epoch,
    epoch_digest: epochDigest,
    epoch_url: `${base}/registry/epochs/${epoch.epoch_id}`,
    trust_anchor: trustedAnchor,
    fetched_trust_anchor: trustAnchor,
    verification,
    pinned: {
      registry_epoch_digest: Boolean(options.expectedEpochDigest),
      registry_trust_anchor: Boolean(pinnedTrustAnchor(options))
    }
  };
}

export async function fetchOperatorRegistryBinding(registryUrl, operatorId, options = {}, fetchImpl = fetch) {
  if (!registryUrl || !operatorId) {
    return null;
  }
  const base = registryUrl.replace(/\/$/, "");
  const [recordResponse, publicKeyResponse] = await Promise.all([
    fetchImpl(`${base}/operators/${encodeURIComponent(operatorId)}`),
    fetchImpl(`${base}/registry/public-key`)
  ]);
  const record = await recordResponse.json();
  const trustAnchor = await publicKeyResponse.json();
  if (!recordResponse.ok) {
    throw new Error(record.error || `operator registry returned ${recordResponse.status}`);
  }
  if (!publicKeyResponse.ok) {
    throw new Error(trustAnchor.error || `registry public key returned ${publicKeyResponse.status}`);
  }
  const trustedAnchor = pinnedTrustAnchor(options) || trustAnchor;
  verifyFetchedTrustAnchor(trustAnchor, trustedAnchor);
  const verification = verifyOperatorRegistryRecord(record, { [trustedAnchor.key_id]: trustedAnchor.public_key_pem });
  return {
    operator_record: record,
    operator_record_digest: digestValue(record),
    operator_record_url: `${base}/operators/${encodeURIComponent(record.operator_id)}`,
    registry_trust_anchor: trustedAnchor,
    fetched_registry_trust_anchor: trustAnchor,
    verification,
    pinned: {
      registry_trust_anchor: Boolean(pinnedTrustAnchor(options))
    }
  };
}

function pinnedTrustAnchor(options) {
  if (!options?.trustAnchorKeyId && !options?.trustAnchorPublicKeyPem) {
    return null;
  }
  if (!options.trustAnchorKeyId || !options.trustAnchorPublicKeyPem) {
    throw new Error("registry trust anchor pin requires both key id and public key PEM");
  }
  return {
    key_id: options.trustAnchorKeyId,
    public_key_pem: options.trustAnchorPublicKeyPem
  };
}

function verifyFetchedTrustAnchor(fetched, trusted) {
  if (!fetched || !trusted) {
    return;
  }
  if (fetched.key_id !== trusted.key_id || fetched.public_key_pem !== trusted.public_key_pem) {
    throw new Error("registry trust anchor response does not match pinned trust anchor");
  }
}

function verifyExpectedDigest(label, actual, expected) {
  if (expected && actual !== expected) {
    throw new Error(`${label} digest mismatch: expected=${expected} actual=${actual}`);
  }
}

async function witnessEntry({ witness, tier, policyHash, fetchImpl }) {
  const base = witness.url.replace(/\/$/, "");
  const response = await fetchImpl(`${base}/v1/public-key`);
  const publicKey = await response.json();
  if (!response.ok) {
    throw new Error(publicKey.error || `${witness.id} public key request returned ${response.status}`);
  }
  return {
    witness_id: witness.id,
    tier,
    key_id: publicKey.key_id,
    public_key_pem: publicKey.public_key_pem,
    authorized_workflows: ["email.send"],
    authorized_policy_hashes: [policyHash],
    valid_from: REGISTRY_VALID_FROM,
    valid_until: null,
    status: "active",
    status_events: [],
    operator: "amotivv-demo"
  };
}

import {
  WITNESS_REGISTRY_EPOCH_VERSION,
  canonicalize,
  loadOrCreateEd25519Signer,
  signEd25519,
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
export const REGISTRY_EPOCH_ID = "email-demo-epoch-001";
export const REGISTRY_VALID_FROM = "2026-04-28T00:00:00.000Z";

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

export async function fetchRegistryBinding(registryUrl, fetchImpl = fetch) {
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
  const verification = verifyWitnessRegistryEpoch(epoch, { [trustAnchor.key_id]: trustAnchor.public_key_pem });
  return {
    epoch,
    epoch_digest: witnessRegistryEpochDigest(epoch),
    epoch_url: `${base}/registry/epochs/${epoch.epoch_id}`,
    trust_anchor: trustAnchor,
    verification
  };
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

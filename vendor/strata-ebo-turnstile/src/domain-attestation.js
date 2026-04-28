import { canonicalize } from "./canonicalize.js";
import { sha256Hex, signEd25519, verifyEd25519 } from "./crypto.js";

export const DOMAIN_ATTESTATION_VERSION = "turnstile.domain-attestation.v1";

export function certificateBundleDigest({ receipts, checkpoint, keyring, transparencyLogEntries, verification }) {
  return sha256Hex(canonicalize({
    receipts,
    checkpoint,
    keyring,
    transparency_log_entries: transparencyLogEntries,
    verification_summary: verification ? {
      ok: verification.ok,
      final_state_root: verification.session?.finalStateRoot,
      checkpoint_ok: verification.checkpoint?.ok,
      tinfoil_ok: verification.tinfoil?.ok
    } : null
  }));
}

export function createDomainAttestation({
  attestationId,
  attestorId,
  domain,
  assuranceTier = "domain",
  certificateDigest,
  registryEpochId,
  claim,
  evidenceRefs = [],
  issuedAt = new Date().toISOString()
}) {
  return {
    version: DOMAIN_ATTESTATION_VERSION,
    attestation_id: attestationId,
    attestor_id: attestorId,
    domain,
    assurance_tier: assuranceTier,
    certificate_digest: certificateDigest,
    registry_epoch_id: registryEpochId,
    claim,
    evidence_refs: evidenceRefs,
    issued_at: issuedAt
  };
}

export function domainAttestationPayload(attestation) {
  const { signature: _signature, ...payload } = attestation;
  return payload;
}

export function domainAttestationDigest(attestation) {
  return sha256Hex(canonicalize(domainAttestationPayload(attestation)));
}

export function domainAttestationSigningMessage(attestation) {
  return `${DOMAIN_ATTESTATION_VERSION}\n${domainAttestationDigest(attestation)}`;
}

export function signDomainAttestation(attestation, signer) {
  return {
    ...attestation,
    signature: {
      key_id: signer.keyId,
      alg: "Ed25519",
      sig: signEd25519(domainAttestationSigningMessage(attestation), signer.privateKey)
    }
  };
}

export function verifyDomainAttestation(attestation, { certificateDigest, attestorKeyring }) {
  const errors = [];

  if (!attestation || attestation.version !== DOMAIN_ATTESTATION_VERSION) {
    return { ok: false, errors: ["invalid domain attestation version"] };
  }
  if (attestation.certificate_digest !== certificateDigest) {
    errors.push("domain attestation certificate digest mismatch");
  }

  const signature = attestation.signature;
  const publicKey = signature && attestorKeyring?.[signature.key_id];
  if (!signature || signature.alg !== "Ed25519") {
    errors.push("domain attestation missing Ed25519 signature");
  } else if (!publicKey) {
    errors.push(`unknown domain attestor key: ${signature.key_id}`);
  } else if (!verifyEd25519(domainAttestationSigningMessage(attestation), signature.sig, publicKey)) {
    errors.push(`invalid domain attestation signature: ${signature.key_id}`);
  }

  return {
    ok: errors.length === 0,
    errors,
    attestation_digest: domainAttestationDigest(attestation)
  };
}

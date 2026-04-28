import { canonicalize } from "./canonicalize.js";
import { sha256Hex, signEd25519, verifyEd25519 } from "./crypto.js";
import { verifyQuorumCertificate } from "./quorum.js";
import { verifyTransparencyInclusion } from "./transparency-log.js";

export const STAMPED_OUTPUT_VERSION = "turnstile.stamped-output.v1";

export function createStampedOutput({
  stampId,
  sessionId,
  sourceReceiptRoot,
  observationReceiptRoot,
  outputDigest,
  outputSchemaHash = null,
  outputRef = null,
  contentType = "application/json",
  admissionManifestHash = null,
  verifierProfileHash = null,
  agentAttestationRef = null,
  gatewayAttestationRef = null,
  verifierAttestationRef = null,
  checkpointRef = null,
  receiptLogRef = null,
  certificateRef = null,
  transparencyLogRef = null,
  issuedAt = new Date().toISOString()
}) {
  return {
    version: STAMPED_OUTPUT_VERSION,
    stamp_id: stampId,
    session_id: sessionId,
    source_receipt_root: sourceReceiptRoot,
    observation_receipt_root: observationReceiptRoot,
    output_digest: outputDigest,
    output_schema_hash: outputSchemaHash,
    output_ref: outputRef,
    content_type: contentType,
    admission_manifest_hash: admissionManifestHash,
    verifier_profile_hash: verifierProfileHash,
    agent_attestation_ref: agentAttestationRef,
    gateway_attestation_ref: gatewayAttestationRef,
    verifier_attestation_ref: verifierAttestationRef,
    checkpoint_ref: checkpointRef,
    receipt_log_ref: receiptLogRef,
    certificate_ref: certificateRef,
    transparency_log_ref: transparencyLogRef,
    issued_at: issuedAt
  };
}

export function stampedOutputPayload(stamp) {
  const {
    gateway_signature: gatewaySignature,
    quorum_certificate: quorumCertificate,
    transparency_log_inclusion: transparencyLogInclusion,
    ...payload
  } = stamp;
  return payload;
}

export function stampedOutputDigest(stamp) {
  return sha256Hex(canonicalize(stamp));
}

export function stampedOutputPayloadDigest(stamp) {
  return sha256Hex(canonicalize(stampedOutputPayload(stamp)));
}

export function stampedOutputSigningMessage(stamp) {
  return `${STAMPED_OUTPUT_VERSION}\n${stampedOutputPayloadDigest(stamp)}`;
}

export function signStampedOutput(stamp, signer) {
  return {
    ...stamp,
    gateway_signature: {
      key_id: signer.keyId,
      alg: "Ed25519",
      sig: signEd25519(stampedOutputSigningMessage(stamp), signer.privateKey)
    }
  };
}

export function verifyStampedOutput(stamp, { output = null, receipts = [], keyring, transparencyLogEntries = null, requireTransparencyLog = false, requireQuorum = false } = {}) {
  const errors = [];

  if (!stamp || stamp.version !== STAMPED_OUTPUT_VERSION) {
    return { ok: false, errors: ["invalid stamped output version"] };
  }

  const signature = stamp.gateway_signature;
  const publicKey = signature && keyring?.[signature.key_id];
  if (!signature || signature.alg !== "Ed25519") {
    errors.push("stamped output missing Ed25519 gateway signature");
  } else if (!publicKey) {
    errors.push(`unknown stamped output signer key: ${signature.key_id}`);
  } else if (!verifyEd25519(stampedOutputSigningMessage(stamp), signature.sig, publicKey)) {
    errors.push(`invalid stamped output signature: ${signature.key_id}`);
  }

  if (output !== null) {
    const outputDigest = sha256Hex(canonicalize(output));
    if (outputDigest !== stamp.output_digest) {
      errors.push("stamped output digest does not match supplied output");
    }
  }

  const source = receipts.find((receipt) => receipt.state_root === stamp.source_receipt_root);
  if (receipts.length > 0 && !source) {
    errors.push("stamped output source receipt not found");
  }

  const observation = receipts.find((receipt) => receipt.state_root === stamp.observation_receipt_root);
  if (receipts.length > 0 && !observation) {
    errors.push("stamped output observation receipt not found");
  }

  if (observation?.body?.observed_digest && observation.body.observed_digest !== stamp.output_digest) {
    errors.push("stamped output observation digest mismatch");
  }

  if (stamp.quorum_certificate) {
    const quorum = verifyQuorumCertificate(stampedOutputPayload(stamp), stamp.quorum_certificate, keyring);
    errors.push(...quorum.errors.map((error) => `stamped output quorum: ${error}`));
  } else if (requireQuorum) {
    errors.push("stamped output missing quorum certificate");
  }

  if (stamp.transparency_log_inclusion) {
    const transparency = verifyTransparencyInclusion(stampedOutputPayload(stamp), stamp.transparency_log_inclusion, transparencyLogEntries, keyring);
    errors.push(...transparency.errors.map((error) => `stamped output transparency: ${error}`));
  } else if (requireTransparencyLog) {
    errors.push("stamped output missing transparency log inclusion");
  }

  return { ok: errors.length === 0, errors };
}

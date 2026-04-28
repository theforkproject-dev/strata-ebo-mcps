import { canonicalize } from "./canonicalize.js";
import { sha256Hex, signEd25519, verifyEd25519 } from "./crypto.js";

export const QUORUM_CERT_VERSION = "turnstile.quorum-certificate.v1";

export function quorumSubjectDigest(subject) {
  return sha256Hex(canonicalize(subject));
}

export function quorumSigningMessage(subject) {
  return `${QUORUM_CERT_VERSION}\n${quorumSubjectDigest(subject)}`;
}

export function createQuorumCertificate(subject, witnesses, { threshold }) {
  const signatures = [];
  const refusals = [];

  for (const witness of witnesses) {
    try {
      signatures.push(witness.sign(subject));
    } catch (error) {
      refusals.push({ witness_id: witness.id, reason: error.message });
    }
  }

  if (signatures.length < threshold) {
    throw new Error(`Quorum not met: got ${signatures.length}, need ${threshold}`);
  }

  return {
    version: QUORUM_CERT_VERSION,
    threshold,
    subject_digest: quorumSubjectDigest(subject),
    signatures: signatures.slice(0, threshold),
    refusals
  };
}

export async function createQuorumCertificateAsync(subject, witnesses, { threshold }) {
  const results = await Promise.all(witnesses.map(async (witness) => {
    try {
      return { signature: await witness.sign(subject) };
    } catch (error) {
      return { refusal: { witness_id: witness.id, reason: error.message } };
    }
  }));

  const signatures = results.filter((result) => result.signature).map((result) => result.signature);
  const refusals = results.filter((result) => result.refusal).map((result) => result.refusal);

  if (signatures.length < threshold) {
    throw new Error(`Quorum not met: got ${signatures.length}, need ${threshold}`);
  }

  return {
    version: QUORUM_CERT_VERSION,
    threshold,
    subject_digest: quorumSubjectDigest(subject),
    signatures: signatures.slice(0, threshold),
    refusals
  };
}

export function verifyQuorumCertificate(subject, certificate, keyring) {
  const errors = [];

  if (!certificate || certificate.version !== QUORUM_CERT_VERSION) {
    return { ok: false, errors: ["invalid quorum certificate version"] };
  }

  if (certificate.subject_digest !== quorumSubjectDigest(subject)) {
    errors.push("quorum certificate subject digest mismatch");
  }

  if (!Number.isInteger(certificate.threshold) || certificate.threshold < 1) {
    errors.push("quorum certificate threshold is invalid");
  }

  const seen = new Set();
  let valid = 0;
  for (const signature of certificate.signatures ?? []) {
    if (seen.has(signature.witness_id)) {
      errors.push(`duplicate witness signature: ${signature.witness_id}`);
      continue;
    }
    seen.add(signature.witness_id);

    const publicKey = keyring[signature.key_id];
    if (!publicKey) {
      errors.push(`unknown witness key: ${signature.key_id}`);
      continue;
    }
    if (signature.alg !== "Ed25519") {
      errors.push(`unsupported witness signature algorithm: ${signature.alg}`);
      continue;
    }
    if (!verifyEd25519(quorumSigningMessage(subject), signature.sig, publicKey)) {
      errors.push(`invalid witness signature: ${signature.witness_id}`);
      continue;
    }
    valid += 1;
  }

  if (valid < certificate.threshold) {
    errors.push(`quorum threshold not met: ${valid}/${certificate.threshold}`);
  }

  return { ok: errors.length === 0, errors };
}

export function signQuorumSubject(subject, witness) {
  return {
    witness_id: witness.id,
    key_id: witness.keyId,
    alg: "Ed25519",
    sig: signEd25519(quorumSigningMessage(subject), witness.privateKey)
  };
}

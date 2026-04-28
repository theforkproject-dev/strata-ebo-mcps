import { canonicalize } from "./canonicalize.js";
import { sha256Hex, signEd25519, verifyEd25519 } from "./crypto.js";
import { quorumSubjectDigest, verifyQuorumCertificate } from "./quorum.js";

export const WITNESS_REGISTRY_EPOCH_VERSION = "turnstile.witness-registry-epoch.v1";
export const WITNESS_TIERS = Object.freeze({
  mechanical: 1,
  policy: 2,
  domain: 3
});

export function witnessRegistryEpochPayload(epoch) {
  const { signatures: _signatures, ...payload } = epoch;
  return payload;
}

export function witnessRegistryEpochDigest(epoch) {
  return sha256Hex(canonicalize(witnessRegistryEpochPayload(epoch)));
}

export function witnessRegistryEpochSigningMessage(epoch) {
  return `${WITNESS_REGISTRY_EPOCH_VERSION}\n${witnessRegistryEpochDigest(epoch)}`;
}

export function signWitnessRegistryEpoch(epoch, signer) {
  return {
    ...epoch,
    signatures: [
      ...(epoch.signatures ?? []),
      {
        key_id: signer.keyId,
        alg: "Ed25519",
        sig: signEd25519(witnessRegistryEpochSigningMessage(epoch), signer.privateKey)
      }
    ]
  };
}

export function verifyWitnessRegistryEpoch(epoch, trustAnchors) {
  const errors = [];

  if (!epoch || epoch.version !== WITNESS_REGISTRY_EPOCH_VERSION) {
    return { ok: false, errors: ["invalid witness registry epoch version"] };
  }

  if (!epoch.registry_id) {
    errors.push("registry_id missing");
  }
  if (!epoch.epoch_id) {
    errors.push("epoch_id missing");
  }
  if (!isIsoDate(epoch.valid_from)) {
    errors.push("valid_from must be an ISO timestamp");
  }
  if (epoch.valid_until !== null && !isIsoDate(epoch.valid_until)) {
    errors.push("valid_until must be null or an ISO timestamp");
  }
  if (!Array.isArray(epoch.witnesses)) {
    errors.push("witnesses must be an array");
  }

  const anchors = normalizeTrustAnchors(trustAnchors);
  if (!Array.isArray(epoch.signatures) || epoch.signatures.length === 0) {
    errors.push("witness registry epoch has no signatures");
  } else {
    const message = witnessRegistryEpochSigningMessage(epoch);
    let valid = 0;
    for (const signature of epoch.signatures) {
      const publicKey = anchors[signature.key_id];
      if (signature.alg !== "Ed25519") {
        errors.push(`unsupported registry signature algorithm: ${signature.alg}`);
      } else if (!publicKey) {
        errors.push(`unknown registry signing key: ${signature.key_id}`);
      } else if (!verifyEd25519(message, signature.sig, publicKey)) {
        errors.push(`invalid registry signature: ${signature.key_id}`);
      } else {
        valid += 1;
      }
    }
    if (valid === 0) {
      errors.push("no valid registry authority signature");
    }
  }

  return { ok: errors.length === 0, errors, epoch_digest: witnessRegistryEpochDigest(epoch) };
}

export function collectWitnessedSubjects({ receipts = [], checkpoint = null } = {}) {
  const subjects = [];

  for (const receipt of receipts) {
    const body = receipt.body ?? {};
    if (receipt.kind === "session.start" && body.quorum_certificate) {
      subjects.push({ label: "session.start", signing_time: receipt.issued_at, subject: body.session_start_subject, certificate: body.quorum_certificate });
    }
    if (receipt.kind === "intent.grant" && body.quorum_certificate) {
      subjects.push({ label: "intent.grant", signing_time: receipt.issued_at, subject: body.intent, certificate: body.quorum_certificate });
    }
    if (receipt.kind === "observation" && body.observation_subject && body.quorum_certificate) {
      subjects.push({ label: "observation", signing_time: receipt.issued_at, subject: body.observation_subject, certificate: body.quorum_certificate });
    }
    if (receipt.kind === "session.end" && body.quorum_certificate) {
      subjects.push({ label: "session.end", signing_time: receipt.issued_at, subject: body.session_end_subject, certificate: body.quorum_certificate });
    }
  }

  if (checkpoint?.quorum_certificate) {
    subjects.push({
      label: "checkpoint",
      signing_time: checkpoint.statement?.issued_at,
      subject: checkpoint.statement,
      certificate: checkpoint.quorum_certificate
    });
  }

  return subjects;
}

export function verifyWitnessAuthority({
  receipts,
  checkpoint = null,
  keyring,
  registryEpoch,
  trustAnchors,
  workflowId,
  policyHash,
  requiredTier = "mechanical"
}) {
  const errors = [];
  const warnings = [];
  const checks = [];
  const epoch = verifyWitnessRegistryEpoch(registryEpoch, trustAnchors);
  errors.push(...epoch.errors.map((error) => `registry epoch: ${error}`));

  const subjects = collectWitnessedSubjects({ receipts, checkpoint });
  if (subjects.length === 0) {
    errors.push("certificate contains no witnessed subjects");
  }

  const registryByKey = new Map((registryEpoch?.witnesses ?? []).map((witness) => [witness.key_id, witness]));
  const requiredTierRank = tierRank(requiredTier);

  for (const item of subjects) {
    const quorum = verifyQuorumCertificate(item.subject, item.certificate, keyring);
    const itemErrors = [...quorum.errors.map((error) => `quorum: ${error}`)];
    const authorized = [];

    for (const signature of item.certificate.signatures ?? []) {
      const witness = registryByKey.get(signature.key_id);
      const signatureErrors = [];

      if (!witness) {
        signatureErrors.push(`witness key ${signature.key_id} is not in registry epoch ${registryEpoch?.epoch_id}`);
      } else {
        if (witness.witness_id !== signature.witness_id) {
          signatureErrors.push(`witness_id mismatch for ${signature.key_id}: certificate=${signature.witness_id} registry=${witness.witness_id}`);
        }
        if (normalizePem(witness.public_key_pem) !== normalizePem(keyring[signature.key_id])) {
          signatureErrors.push(`registry public key does not match certificate keyring for ${signature.key_id}`);
        }
        if (!isAuthorizedForWorkflow(witness, workflowId)) {
          signatureErrors.push(`${signature.key_id} is not authorized for workflow ${workflowId}`);
        }
        if (!isAuthorizedForPolicy(witness, policyHash)) {
          signatureErrors.push(`${signature.key_id} is not authorized for policy ${policyHash}`);
        }
        if (tierRank(witness.tier) < requiredTierRank) {
          signatureErrors.push(`${signature.key_id} tier ${witness.tier} is below required tier ${requiredTier}`);
        }
        signatureErrors.push(...authorizationTimeErrors(witness, item.signing_time));
      }

      if (signatureErrors.length === 0) {
        authorized.push(signature.key_id);
      } else {
        itemErrors.push(...signatureErrors.map((error) => `${item.label}: ${error}`));
      }
    }

    if (authorized.length < item.certificate.threshold) {
      itemErrors.push(`${item.label}: authorized quorum threshold not met: ${authorized.length}/${item.certificate.threshold}`);
    }

    checks.push({
      label: item.label,
      signing_time: item.signing_time,
      subject_digest: quorumSubjectDigest(item.subject),
      quorum_threshold: item.certificate.threshold,
      authorized_witness_keys: authorized,
      ok: itemErrors.length === 0,
      errors: itemErrors
    });
    errors.push(...itemErrors);
  }

  if (registryEpoch?.status_semantics?.deprecated) {
    warnings.push("deprecated witnesses remain valid for signatures created before deprecation; they must not sign new actions after deprecation takes effect");
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    registry_epoch_digest: epoch.epoch_digest,
    workflow_id: workflowId,
    policy_hash: policyHash,
    required_tier: requiredTier,
    checks
  };
}

function normalizeTrustAnchors(trustAnchors) {
  if (!trustAnchors) {
    return {};
  }
  if (trustAnchors.keyring) {
    return trustAnchors.keyring;
  }
  if (trustAnchors.key_id && trustAnchors.public_key_pem) {
    return { [trustAnchors.key_id]: trustAnchors.public_key_pem };
  }
  return trustAnchors;
}

function authorizationTimeErrors(witness, signingTime) {
  const errors = [];
  if (!isIsoDate(signingTime)) {
    return [`invalid signing time for ${witness.key_id}: ${signingTime}`];
  }
  const signedAt = new Date(signingTime).getTime();

  if (isIsoDate(witness.valid_from) && signedAt < new Date(witness.valid_from).getTime()) {
    errors.push(`${witness.key_id} was not valid until ${witness.valid_from}`);
  }
  if (isIsoDate(witness.valid_until) && signedAt >= new Date(witness.valid_until).getTime()) {
    errors.push(`${witness.key_id} authorization expired at ${witness.valid_until}`);
  }

  const status = statusAt(witness.status_events ?? [], signingTime, witness.status ?? "active");
  if (!["active"].includes(status.status)) {
    errors.push(`${witness.key_id} status at signing time was ${status.status}`);
  }

  for (const event of witness.status_events ?? []) {
    const invalidatesFrom = event.invalidates_from ?? event.compromise_from;
    if (["revoked", "compromised"].includes(event.status) && isIsoDate(invalidatesFrom) && signedAt >= new Date(invalidatesFrom).getTime()) {
      errors.push(`${witness.key_id} ${event.status} event invalidates signatures from ${invalidatesFrom}`);
    }
  }

  return errors;
}

function statusAt(events, signingTime, fallback) {
  const signedAt = new Date(signingTime).getTime();
  return [...events]
    .filter((event) => isIsoDate(event.effective_at) && new Date(event.effective_at).getTime() <= signedAt)
    .sort((left, right) => new Date(left.effective_at).getTime() - new Date(right.effective_at).getTime())
    .at(-1) ?? { status: fallback };
}

function isAuthorizedForWorkflow(witness, workflowId) {
  return (witness.authorized_workflows ?? []).includes(workflowId);
}

function isAuthorizedForPolicy(witness, policyHash) {
  return (witness.authorized_policy_hashes ?? []).includes(policyHash);
}

function tierRank(tier) {
  return WITNESS_TIERS[tier] ?? 0;
}

function normalizePem(value) {
  return String(value ?? "").replace(/\s+/g, "");
}

function isIsoDate(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

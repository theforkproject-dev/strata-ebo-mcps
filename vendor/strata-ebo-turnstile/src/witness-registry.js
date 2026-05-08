import { canonicalize } from "./canonicalize.js";
import { sha256Hex, signEd25519, verifyEd25519 } from "./crypto.js";
import { quorumSubjectDigest, verifyQuorumCertificate } from "./quorum.js";
import { verifyWitnessSignRequest } from "./witness-request.js";

export const WITNESS_REGISTRY_EPOCH_VERSION = "turnstile.witness-registry-epoch.v1";
export const WITNESS_REGISTRY_POINTER_VERSION = "turnstile.witness-registry-current.v1";
export const WITNESS_TIERS = Object.freeze({
  mechanical: 1,
  policy: 2,
  domain: 3
});
const WITNESS_STATUSES = new Set(["active", "deprecated", "revoked", "compromised"]);

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

export function witnessRegistryPointerPayload(pointer) {
  const { signatures: _signatures, ...payload } = pointer;
  return payload;
}

export function witnessRegistryPointerDigest(pointer) {
  return sha256Hex(canonicalize(witnessRegistryPointerPayload(pointer)));
}

export function witnessRegistryPointerSigningMessage(pointer) {
  return `${WITNESS_REGISTRY_POINTER_VERSION}\n${witnessRegistryPointerDigest(pointer)}`;
}

export function signWitnessRegistryPointer(pointer, signer) {
  return {
    ...pointer,
    signatures: [
      ...(pointer.signatures ?? []),
      {
        key_id: signer.keyId,
        alg: "Ed25519",
        sig: signEd25519(witnessRegistryPointerSigningMessage(pointer), signer.privateKey)
      }
    ]
  };
}

export function verifyWitnessRegistryPointer(pointer, trustAnchors) {
  const errors = [];

  if (!pointer || pointer.version !== WITNESS_REGISTRY_POINTER_VERSION) {
    return { ok: false, errors: ["invalid witness registry pointer version"] };
  }

  for (const field of ["registry_id", "pointer_id", "epoch_id", "registry_epoch_digest", "registry_epoch_url", "registry_trust_anchors_url", "published_at"]) {
    if (!pointer[field]) {
      errors.push(`${field} missing`);
    }
  }
  if (pointer.valid_from !== undefined && pointer.valid_from !== null && !isIsoDate(pointer.valid_from)) {
    errors.push("valid_from must be an ISO timestamp when present");
  }
  if (pointer.valid_until !== undefined && pointer.valid_until !== null && !isIsoDate(pointer.valid_until)) {
    errors.push("valid_until must be an ISO timestamp when present");
  }
  if (pointer.refresh_by !== undefined && pointer.refresh_by !== null && !isIsoDate(pointer.refresh_by)) {
    errors.push("refresh_by must be an ISO timestamp when present");
  }
  if (!isIsoDate(pointer.published_at)) {
    errors.push("published_at must be an ISO timestamp");
  }

  const anchors = normalizeTrustAnchors(trustAnchors);
  if (!Array.isArray(pointer.signatures) || pointer.signatures.length === 0) {
    errors.push("witness registry pointer has no signatures");
  } else {
    const message = witnessRegistryPointerSigningMessage(pointer);
    let valid = 0;
    for (const signature of pointer.signatures) {
      const publicKey = anchors[signature.key_id];
      if (signature.alg !== "Ed25519") {
        errors.push(`unsupported registry pointer signature algorithm: ${signature.alg}`);
      } else if (!publicKey) {
        errors.push(`unknown registry pointer signing key: ${signature.key_id}`);
      } else if (!verifyEd25519(message, signature.sig, publicKey)) {
        errors.push(`invalid registry pointer signature: ${signature.key_id}`);
      } else {
        valid += 1;
      }
    }
    if (valid === 0) {
      errors.push("no valid registry pointer authority signature");
    }
  }

  return { ok: errors.length === 0, errors, pointer_digest: witnessRegistryPointerDigest(pointer) };
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
  if (epoch.gateways !== undefined && !Array.isArray(epoch.gateways)) {
    errors.push("gateways must be an array when present");
  }
  if (Array.isArray(epoch.witnesses)) {
    errors.push(...validateRegistryEntries(epoch.witnesses, "witness", [
      "witness_id",
      "key_id",
      "public_key_pem",
      "tier",
      "authorized_workflows",
      "authorized_policy_hashes",
      "valid_from",
      "valid_until",
      "status"
    ]));
  }
  if (Array.isArray(epoch.gateways)) {
    errors.push(...validateRegistryEntries(epoch.gateways, "gateway", [
      "gateway_id",
      "key_id",
      "public_key_pem",
      "authorized_workflows",
      "authorized_policy_hashes",
      "valid_from",
      "valid_until",
      "status"
    ]));
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

export function registryGatewayKeyring(registryEpoch) {
  return Object.fromEntries((registryEpoch?.gateways ?? []).map((gateway) => [gateway.key_id, gateway.public_key_pem]));
}

export function verifyWitnessSignRequestAuthority({
  request,
  registryEpoch,
  trustAnchors,
  now = new Date().toISOString(),
  maxFutureSkewMs,
  expectedWitnessId = null,
  expectedWitnessKeyId = null,
  expectedWitnessPublicKeyPem = null,
  expectedWitnessEpochId = null,
  expectedWorkflowId = null,
  requiredTier = "mechanical",
  requireExactTier = true
}) {
  const errors = [];
  const warnings = [];
  const epoch = verifyWitnessRegistryEpoch(registryEpoch, trustAnchors);
  errors.push(...epoch.errors.map((error) => `registry epoch: ${error}`));

  const gatewayByKey = new Map((registryEpoch?.gateways ?? []).map((gateway) => [gateway.key_id, gateway]));
  const gateway = gatewayByKey.get(request?.gateway_key_id);
  const gatewayKeyring = registryGatewayKeyring(registryEpoch);
  const requestVerification = verifyWitnessSignRequest(request, {
    gatewayKeyring,
    now,
    maxFutureSkewMs,
    expectedGatewayId: gateway?.gateway_id ?? null,
    expectedGatewayKeyId: gateway?.key_id ?? null,
    expectedWitnessId,
    expectedWitnessEpochId,
    expectedRegistryEpochId: registryEpoch?.epoch_id,
    expectedWorkflowId
  });
  errors.push(...requestVerification.errors.map((error) => `request: ${error}`));

  if (!gateway) {
    errors.push(`gateway key ${request?.gateway_key_id} is not in registry epoch ${registryEpoch?.epoch_id}`);
  } else {
    if (gateway.gateway_id !== request.gateway_id) {
      errors.push(`gateway_id mismatch for ${request.gateway_key_id}: request=${request.gateway_id} registry=${gateway.gateway_id}`);
    }
    if (!isAuthorizedForWorkflow(gateway, request.workflow_id)) {
      errors.push(`${request.gateway_key_id} is not authorized for workflow ${request.workflow_id}`);
    }
    const policyHash = request.subject?.policy_hash ?? request.subject?.governance_policy_hash;
    if (policyHash && !isAuthorizedForPolicy(gateway, policyHash)) {
      errors.push(`${request.gateway_key_id} is not authorized for policy ${policyHash}`);
    }
    errors.push(...authorizationTimeErrors(gateway, now));
  }

  const witness = expectedWitnessKeyId
    ? (registryEpoch?.witnesses ?? []).find((candidate) => candidate.key_id === expectedWitnessKeyId)
    : null;
  if (expectedWitnessKeyId && !witness) {
    errors.push(`witness key ${expectedWitnessKeyId} is not in registry epoch ${registryEpoch?.epoch_id}`);
  } else if (witness) {
    if (witness.witness_id !== request.witness_id) {
      errors.push(`witness_id mismatch for ${expectedWitnessKeyId}: request=${request.witness_id} registry=${witness.witness_id}`);
    }
    if (expectedWitnessPublicKeyPem && normalizePem(witness.public_key_pem) !== normalizePem(expectedWitnessPublicKeyPem)) {
      errors.push(`witness public key mismatch for ${expectedWitnessKeyId}: local witness key does not match registry epoch`);
    }
    if (witness.witness_epoch_id && witness.witness_epoch_id !== request.witness_epoch_id) {
      errors.push(`witness_epoch_id mismatch for ${expectedWitnessKeyId}: request=${request.witness_epoch_id} registry=${witness.witness_epoch_id}`);
    }
    if (!isAuthorizedForWorkflow(witness, request.workflow_id)) {
      errors.push(`${expectedWitnessKeyId} is not authorized for workflow ${request.workflow_id}`);
    }
    const policyHash = request.subject?.policy_hash ?? request.subject?.governance_policy_hash;
    if (policyHash && !isAuthorizedForPolicy(witness, policyHash)) {
      errors.push(`${expectedWitnessKeyId} is not authorized for policy ${policyHash}`);
    }
    if (!isTierAuthorized(witness.tier, requiredTier, requireExactTier)) {
      errors.push(`${expectedWitnessKeyId} tier ${witness.tier} does not satisfy required tier ${requiredTier}`);
    }
    errors.push(...authorizationTimeErrors(witness, now));
  }

  if (registryEpoch?.status_semantics?.deprecated) {
    warnings.push("deprecated witnesses remain valid for signatures created before deprecation; they must not sign new actions after deprecation takes effect");
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    registry_epoch_digest: epoch.epoch_digest,
    request_digest: requestVerification.request_digest,
    subject_digest: requestVerification.subject_digest,
    gateway_key_id: request?.gateway_key_id,
    witness_key_id: expectedWitnessKeyId,
    workflow_id: request?.workflow_id,
    required_tier: requiredTier,
    require_exact_tier: requireExactTier
  };
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
  requiredTier = "mechanical",
  requireExactTier = true,
  requireGuardEvidence = false,
  allowedGuardBackends = undefined,
  allowedGuardStatuses = undefined
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

  for (const item of subjects) {
    const quorum = verifyQuorumCertificate(item.subject, item.certificate, keyring, {
      requireGuardEvidence,
      allowedGuardBackends,
      allowedGuardStatuses
    });
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
        if (!isTierAuthorized(witness.tier, requiredTier, requireExactTier)) {
          signatureErrors.push(`${signature.key_id} tier ${witness.tier} does not satisfy required tier ${requiredTier}`);
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
      guard_evidence_required: requireGuardEvidence,
      require_exact_tier: requireExactTier,
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
    require_exact_tier: requireExactTier,
    checks
  };
}

function validateRegistryEntries(entries, label, requiredFields) {
  const errors = [];
  const keyIds = new Set();
  for (const [index, entry] of entries.entries()) {
    for (const field of requiredFields) {
      if (entry[field] === undefined || entry[field] === "") {
        errors.push(`${label} ${index} ${field} missing`);
      }
    }

    if (entry.key_id) {
      if (keyIds.has(entry.key_id)) {
        errors.push(`duplicate ${label} key_id: ${entry.key_id}`);
      }
      keyIds.add(entry.key_id);
    }
    if (label === "witness" && entry.tier && !Object.hasOwn(WITNESS_TIERS, entry.tier)) {
      errors.push(`witness ${index} unsupported tier: ${entry.tier}`);
    }
    if (entry.status && !WITNESS_STATUSES.has(entry.status)) {
      errors.push(`${label} ${index} unsupported status: ${entry.status}`);
    }
    if (entry.valid_from !== undefined && !isIsoDate(entry.valid_from)) {
      errors.push(`${label} ${index} valid_from must be an ISO timestamp`);
    }
    if (entry.valid_until !== undefined && entry.valid_until !== null && !isIsoDate(entry.valid_until)) {
      errors.push(`${label} ${index} valid_until must be null or an ISO timestamp`);
    }
    if (entry.authorized_workflows !== undefined && !Array.isArray(entry.authorized_workflows)) {
      errors.push(`${label} ${index} authorized_workflows must be an array`);
    }
    if (entry.authorized_policy_hashes !== undefined && !Array.isArray(entry.authorized_policy_hashes)) {
      errors.push(`${label} ${index} authorized_policy_hashes must be an array`);
    }
  }
  return errors;
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

function isTierAuthorized(actualTier, requiredTier, requireExactTier) {
  return requireExactTier
    ? actualTier === requiredTier
    : tierRank(actualTier) >= tierRank(requiredTier);
}

function normalizePem(value) {
  return String(value ?? "").replace(/\s+/g, "");
}

function isIsoDate(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

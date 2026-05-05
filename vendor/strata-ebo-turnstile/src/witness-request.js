import { canonicalize } from "./canonicalize.js";
import { sha256Hex, signEd25519, verifyEd25519 } from "./crypto.js";

export const WITNESS_SIGN_REQUEST_VERSION = "turnstile.witness-sign-request.v1";

export function witnessSignRequestSubjectDigest(subject) {
  return sha256Hex(canonicalize(subject));
}

export function witnessSignRequestPayload(request) {
  const { signature: _signature, ...payload } = request;
  return payload;
}

export function witnessSignRequestDigest(request) {
  return sha256Hex(canonicalize(witnessSignRequestPayload(request)));
}

export function witnessSignRequestSigningMessage(request) {
  return `${WITNESS_SIGN_REQUEST_VERSION}\n${witnessSignRequestDigest(request)}`;
}

export function createWitnessSignRequest({
  requestId,
  issuedAt = new Date().toISOString(),
  expiresAt,
  ttlMs = 60_000,
  gatewayId,
  gatewayKeyId,
  witnessId,
  witnessEpochId,
  registryEpochId,
  workflowId,
  subject
}, signer) {
  const keyId = gatewayKeyId ?? signer.keyId;
  const expires = expiresAt ?? new Date(new Date(issuedAt).getTime() + ttlMs).toISOString();
  const request = {
    version: WITNESS_SIGN_REQUEST_VERSION,
    request_id: requestId,
    issued_at: issuedAt,
    expires_at: expires,
    gateway_id: gatewayId,
    gateway_key_id: keyId,
    witness_id: witnessId,
    witness_epoch_id: witnessEpochId,
    registry_epoch_id: registryEpochId,
    workflow_id: workflowId,
    subject_digest: witnessSignRequestSubjectDigest(subject),
    subject
  };

  return signWitnessSignRequest(request, signer);
}

export function signWitnessSignRequest(request, signer) {
  return {
    ...witnessSignRequestPayload(request),
    signature: {
      key_id: signer.keyId,
      alg: "Ed25519",
      sig: signEd25519(witnessSignRequestSigningMessage(request), signer.privateKey)
    }
  };
}

export function verifyWitnessSignRequest(request, {
  gatewayKeyring,
  keyring,
  now = new Date().toISOString(),
  maxFutureSkewMs = 30_000,
  expectedGatewayId = null,
  expectedGatewayKeyId = null,
  expectedWitnessId = null,
  expectedWitnessEpochId = null,
  expectedRegistryEpochId = null,
  expectedWorkflowId = null
} = {}) {
  const errors = [];
  let requestDigest = null;
  let subjectDigest = null;

  if (!request || request.version !== WITNESS_SIGN_REQUEST_VERSION) {
    return { ok: false, errors: ["invalid witness sign request version"], request_digest: requestDigest, subject_digest: subjectDigest };
  }

  requireFields(request, errors, [
    "request_id",
    "issued_at",
    "expires_at",
    "gateway_id",
    "gateway_key_id",
    "witness_id",
    "witness_epoch_id",
    "registry_epoch_id",
    "workflow_id",
    "subject_digest"
  ]);

  if (request.subject === undefined || request.subject === null) {
    errors.push("subject missing");
  } else {
    try {
      subjectDigest = witnessSignRequestSubjectDigest(request.subject);
      if (request.subject_digest !== subjectDigest) {
        errors.push("witness sign request subject digest mismatch");
      }
    } catch (error) {
      errors.push(`witness sign request subject is not canonicalizable: ${error.message}`);
    }
  }

  const nowTime = parseTime(now, "now", errors);
  const issuedAt = parseTime(request.issued_at, "issued_at", errors);
  const expiresAt = parseTime(request.expires_at, "expires_at", errors);
  if (Number.isFinite(nowTime) && Number.isFinite(issuedAt) && issuedAt - nowTime > maxFutureSkewMs) {
    errors.push("witness sign request issued_at is in the future");
  }
  if (Number.isFinite(nowTime) && Number.isFinite(expiresAt) && expiresAt <= nowTime) {
    errors.push("witness sign request expired");
  }
  if (Number.isFinite(issuedAt) && Number.isFinite(expiresAt) && expiresAt <= issuedAt) {
    errors.push("witness sign request expires_at must be after issued_at");
  }

  if (expectedGatewayId && request.gateway_id !== expectedGatewayId) {
    errors.push(`witness sign request gateway_id mismatch: expected ${expectedGatewayId}`);
  }
  if (expectedGatewayKeyId && request.gateway_key_id !== expectedGatewayKeyId) {
    errors.push(`witness sign request gateway_key_id mismatch: expected ${expectedGatewayKeyId}`);
  }
  if (expectedWitnessId && request.witness_id !== expectedWitnessId) {
    errors.push(`witness sign request witness_id mismatch: expected ${expectedWitnessId}`);
  }
  if (expectedWitnessEpochId && request.witness_epoch_id !== expectedWitnessEpochId) {
    errors.push(`witness sign request witness_epoch_id mismatch: expected ${expectedWitnessEpochId}`);
  }
  if (expectedRegistryEpochId && request.registry_epoch_id !== expectedRegistryEpochId) {
    errors.push(`witness sign request registry_epoch_id mismatch: expected ${expectedRegistryEpochId}`);
  }
  if (expectedWorkflowId && request.workflow_id !== expectedWorkflowId) {
    errors.push(`witness sign request workflow_id mismatch: expected ${expectedWorkflowId}`);
  }

  const signature = request.signature;
  const publicKeys = gatewayKeyring ?? keyring ?? {};
  const publicKey = signature && publicKeys[signature.key_id];
  if (!signature || signature.alg !== "Ed25519") {
    errors.push("witness sign request missing Ed25519 gateway signature");
  } else if (signature.key_id !== request.gateway_key_id) {
    errors.push("witness sign request signature key_id does not match gateway_key_id");
  } else if (!publicKey) {
    errors.push(`unknown witness sign request gateway key: ${signature.key_id}`);
  } else {
    try {
      if (!verifyEd25519(witnessSignRequestSigningMessage(request), signature.sig, publicKey)) {
        errors.push(`invalid witness sign request gateway signature: ${signature.key_id}`);
      }
    } catch (error) {
      errors.push(`invalid witness sign request gateway signature: ${error.message}`);
    }
  }

  try {
    requestDigest = witnessSignRequestDigest(request);
  } catch (error) {
    errors.push(`witness sign request is not canonicalizable: ${error.message}`);
  }

  return {
    ok: errors.length === 0,
    errors,
    request_digest: requestDigest,
    subject_digest: subjectDigest
  };
}

function requireFields(value, errors, fields) {
  for (const field of fields) {
    if (value[field] === undefined || value[field] === null || value[field] === "") {
      errors.push(`${field} missing`);
    }
  }
}

function parseTime(value, field, errors) {
  const time = new Date(value).getTime();
  if (!Number.isFinite(time)) {
    errors.push(`${field} must be an ISO timestamp`);
  }
  return time;
}

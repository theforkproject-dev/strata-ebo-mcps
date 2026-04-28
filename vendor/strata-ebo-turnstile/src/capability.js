import { canonicalize } from "./canonicalize.js";
import { sha256Hex, signEd25519, verifyEd25519 } from "./crypto.js";

export const CAPABILITY_VERSION = "turnstile.capability.v1";

export function capabilityClaimsDigest(claims) {
  return sha256Hex(canonicalize(claims));
}

export function capabilitySigningMessage(claims) {
  return `${CAPABILITY_VERSION}\n${capabilityClaimsDigest(claims)}`;
}

export function mintCapability(claims, signer) {
  if (!claims.token_id) {
    throw new Error("Capability claims require token_id");
  }

  const token = {
    version: CAPABILITY_VERSION,
    claims: { ...claims },
    issuer_signature: {
      key_id: signer.keyId,
      alg: "Ed25519",
      sig: signEd25519(capabilitySigningMessage(claims), signer.privateKey)
    }
  };

  return token;
}

export function capabilityDigest(token) {
  return sha256Hex(canonicalize(token));
}

export function verifyCapability(token, keyring, options = {}) {
  const errors = [];

  if (!token || token.version !== CAPABILITY_VERSION) {
    errors.push("invalid capability version");
    return { ok: false, errors };
  }

  const signature = token.issuer_signature;
  const publicKey = signature && keyring[signature.key_id];

  if (!signature || signature.alg !== "Ed25519") {
    errors.push("missing Ed25519 issuer signature");
  } else if (!publicKey) {
    errors.push(`unknown capability issuer key: ${signature.key_id}`);
  } else if (!verifyEd25519(capabilitySigningMessage(token.claims), signature.sig, publicKey)) {
    errors.push("invalid capability issuer signature");
  }

  const now = options.now ? new Date(options.now) : new Date();
  if (token.claims.expires_at && new Date(token.claims.expires_at) <= now) {
    errors.push("capability expired");
  }

  if (options.audience && token.claims.tool_audience !== options.audience) {
    errors.push("capability audience mismatch");
  }

  if (options.method && token.claims.method !== options.method) {
    errors.push("capability method mismatch");
  }

  if (options.requestDigest && token.claims.request_digest !== options.requestDigest) {
    errors.push("capability request digest mismatch");
  }

  if (options.policyHash && token.claims.policy_hash !== options.policyHash) {
    errors.push("capability policy hash mismatch");
  }

  if (options.prevStateRoot && token.claims.prev_state_root !== options.prevStateRoot) {
    errors.push("capability previous state root mismatch");
  }

  return { ok: errors.length === 0, errors };
}

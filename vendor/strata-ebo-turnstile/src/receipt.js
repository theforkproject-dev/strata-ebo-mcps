import { canonicalize } from "./canonicalize.js";
import { sha256Hex, signEd25519, verifyEd25519 } from "./crypto.js";

export const RECEIPT_VERSION = "turnstile.receipt.v1";
export const GENESIS_ROOT = "0".repeat(64);

export function receiptPayload(receipt) {
  const { signatures, state_root: stateRoot, ...payload } = receipt;
  return payload;
}

export function receiptPayloadDigest(receipt) {
  return sha256Hex(canonicalize(receiptPayload(receipt)));
}

export function receiptSigningMessage(receipt) {
  return `${RECEIPT_VERSION}\n${receiptPayloadDigest(receipt)}`;
}

export function computeStateRoot(receipt) {
  return sha256Hex(canonicalize({
    protocol: "turnstile-state-root-v1",
    prev_state_root: receipt.prev_state_root,
    payload_digest: receiptPayloadDigest(receipt),
    signatures: receipt.signatures ?? []
  }));
}

export function signReceipt(receipt, signer) {
  const base = {
    version: RECEIPT_VERSION,
    ...receipt
  };

  const next = {
    ...base,
    signatures: [
      ...(receipt.signatures ?? []),
      {
        key_id: signer.keyId,
        alg: "Ed25519",
        sig: signEd25519(receiptSigningMessage(base), signer.privateKey)
      }
    ]
  };

  return {
    ...next,
    state_root: computeStateRoot(next)
  };
}

export function verifyReceiptSignatures(receipt, keyring) {
  const errors = [];

  if (receipt.version !== RECEIPT_VERSION) {
    errors.push(`invalid receipt version: ${receipt.version}`);
  }

  if (!Array.isArray(receipt.signatures) || receipt.signatures.length === 0) {
    errors.push("receipt has no signatures");
    return { ok: false, errors };
  }

  for (const signature of receipt.signatures) {
    const publicKey = keyring[signature.key_id];

    if (signature.alg !== "Ed25519") {
      errors.push(`unsupported signature algorithm for ${signature.key_id}: ${signature.alg}`);
      continue;
    }

    if (!publicKey) {
      errors.push(`unknown receipt signer key: ${signature.key_id}`);
      continue;
    }

    if (!verifyEd25519(receiptSigningMessage(receipt), signature.sig, publicKey)) {
      errors.push(`invalid receipt signature from ${signature.key_id}`);
    }
  }

  return { ok: errors.length === 0, errors };
}

export function verifyReceiptChain(receipts, keyring, options = {}) {
  const errors = [];
  let previousRoot = options.initialRoot ?? GENESIS_ROOT;
  let previousStep = -1;

  receipts.forEach((receipt, index) => {
    if (receipt.prev_state_root !== previousRoot) {
      errors.push(`receipt ${index} prev_state_root mismatch`);
    }

    const expectedRoot = computeStateRoot(receipt);
    if (receipt.state_root !== expectedRoot) {
      errors.push(`receipt ${index} state_root mismatch`);
    }

    if (!Number.isInteger(receipt.step_index) || receipt.step_index < previousStep) {
      errors.push(`receipt ${index} step_index decreased or is invalid`);
    }

    const signatureResult = verifyReceiptSignatures(receipt, keyring);
    errors.push(...signatureResult.errors.map((error) => `receipt ${index}: ${error}`));

    previousRoot = receipt.state_root;
    previousStep = receipt.step_index;
  });

  return {
    ok: errors.length === 0,
    errors,
    finalStateRoot: previousRoot
  };
}

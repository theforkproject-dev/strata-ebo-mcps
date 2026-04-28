import { writeFileSync } from "node:fs";
import { canonicalize } from "./canonicalize.js";
import { sha256Hex, signEd25519, verifyEd25519 } from "./crypto.js";
import { merkleRoot } from "./merkle.js";
import { verifyQuorumCertificate } from "./quorum.js";
import { verifyTransparencyInclusion } from "./transparency-log.js";

export const CHECKPOINT_VERSION = "turnstile.checkpoint.v1";

export function receiptObjectDigest(receipt) {
  return sha256Hex(canonicalize(receipt));
}

export function checkpointStatementDigest(statement) {
  return sha256Hex(canonicalize(statement));
}

export function checkpointDigest(checkpoint) {
  return sha256Hex(canonicalize(checkpoint));
}

export function checkpointSigningMessage(statement) {
  return `${CHECKPOINT_VERSION}\n${checkpointStatementDigest(statement)}`;
}

export function createCheckpointStatement(receipts, options = {}) {
  const receiptDigests = receipts.map(receiptObjectDigest);
  const first = receipts[0];
  const last = receipts[receipts.length - 1];

  return {
    version: CHECKPOINT_VERSION,
    checkpoint_id: options.checkpointId ?? `chk_${Date.now()}`,
    checkpoint_index: options.checkpointIndex ?? 0,
    prev_checkpoint_hash: options.prevCheckpointHash ?? null,
    session_id: options.sessionId ?? first?.session_id ?? null,
    receipt_count: receipts.length,
    receipt_range: {
      from_index: 0,
      to_index: receipts.length === 0 ? null : receipts.length - 1,
      from_step: first?.step_index ?? null,
      to_step: last?.step_index ?? null
    },
    first_state_root: first?.state_root ?? null,
    last_state_root: last?.state_root ?? null,
    merkle_root: merkleRoot(receiptDigests),
    receipt_digests: receiptDigests,
    worm_manifest_digest: options.wormManifestDigest ?? null,
    policy_hash: options.policyHash ?? null,
    verifier_profile_hash: options.verifierProfileHash ?? null,
    issued_at: options.issuedAt ?? new Date().toISOString()
  };
}

export function signCheckpoint(statement, signer) {
  return {
    statement,
    signatures: [
      {
        key_id: signer.keyId,
        alg: "Ed25519",
        sig: signEd25519(checkpointSigningMessage(statement), signer.privateKey)
      }
    ]
  };
}

export function writeCheckpoint(filePath, checkpoint) {
  writeFileSync(filePath, `${canonicalize(checkpoint)}\n`, "utf8");
}

export function verifyCheckpoint(checkpoint, receipts, keyring, options = {}) {
  const errors = [];
  const checkpointReceipts = receipts.slice(0, checkpoint.statement?.receipt_count ?? receipts.length);
  const expected = createCheckpointStatement(checkpointReceipts, {
    checkpointId: checkpoint.statement?.checkpoint_id,
    checkpointIndex: checkpoint.statement?.checkpoint_index,
    prevCheckpointHash: checkpoint.statement?.prev_checkpoint_hash,
    sessionId: checkpoint.statement?.session_id,
    wormManifestDigest: checkpoint.statement?.worm_manifest_digest,
    policyHash: checkpoint.statement?.policy_hash,
    verifierProfileHash: checkpoint.statement?.verifier_profile_hash,
    issuedAt: checkpoint.statement?.issued_at
  });

  if (canonicalize(checkpoint.statement) !== canonicalize(expected)) {
    errors.push("checkpoint statement does not match receipt log");
  }

  if (!Array.isArray(checkpoint.signatures) || checkpoint.signatures.length === 0) {
    errors.push("checkpoint has no signatures");
    return { ok: false, errors };
  }

  for (const signature of checkpoint.signatures) {
    const publicKey = keyring[signature.key_id];
    if (signature.alg !== "Ed25519") {
      errors.push(`unsupported checkpoint signature algorithm for ${signature.key_id}: ${signature.alg}`);
      continue;
    }
    if (!publicKey) {
      errors.push(`unknown checkpoint signer key: ${signature.key_id}`);
      continue;
    }
    if (!verifyEd25519(checkpointSigningMessage(checkpoint.statement), signature.sig, publicKey)) {
      errors.push(`invalid checkpoint signature from ${signature.key_id}`);
    }
  }

  if (checkpoint.quorum_certificate) {
    const quorum = verifyQuorumCertificate(checkpoint.statement, checkpoint.quorum_certificate, keyring);
    errors.push(...quorum.errors.map((error) => `checkpoint quorum: ${error}`));
  } else if (options.requireCheckpointQuorum) {
    errors.push("checkpoint missing quorum certificate");
  }

  if (checkpoint.transparency_log_inclusion) {
    const transparency = verifyTransparencyInclusion(
      checkpoint.statement,
      checkpoint.transparency_log_inclusion,
      options.transparencyLogEntries,
      keyring
    );
    errors.push(...transparency.errors.map((error) => `checkpoint transparency: ${error}`));
  } else if (options.requireCheckpointTransparency) {
    errors.push("checkpoint missing transparency log inclusion");
  }

  return { ok: errors.length === 0, errors };
}

export function verifyCheckpointChain(checkpoints, receipts, keyring, options = {}) {
  const errors = [];
  let previousCheckpoint = null;

  checkpoints.forEach((checkpoint, index) => {
    const result = verifyCheckpoint(checkpoint, receipts, keyring, options);
    errors.push(...result.errors.map((error) => `checkpoint ${index}: ${error}`));

    if (checkpoint.statement?.checkpoint_index !== index) {
      errors.push(`checkpoint ${index}: checkpoint_index must equal ${index}`);
    }

    if (index === 0) {
      if (checkpoint.statement?.prev_checkpoint_hash !== null) {
        errors.push("checkpoint 0: prev_checkpoint_hash must be null");
      }
    } else {
      const expectedPreviousDigest = checkpointDigest(previousCheckpoint);
      if (checkpoint.statement?.prev_checkpoint_hash !== expectedPreviousDigest) {
        errors.push(`checkpoint ${index}: prev_checkpoint_hash mismatch`);
      }

      if (checkpoint.statement?.session_id !== previousCheckpoint.statement?.session_id) {
        errors.push(`checkpoint ${index}: session_id mismatch`);
      }

      if (checkpoint.statement?.receipt_range?.from_index !== 0) {
        errors.push(`checkpoint ${index}: checkpoint range must start at receipt 0 for prefix consistency`);
      }

      if (checkpoint.statement?.receipt_count <= previousCheckpoint.statement?.receipt_count) {
        errors.push(`checkpoint ${index}: receipt_count must increase`);
      }

      if (checkpoint.statement?.receipt_range?.to_index <= previousCheckpoint.statement?.receipt_range?.to_index) {
        errors.push(`checkpoint ${index}: receipt range must extend prior range`);
      }

      const priorDigests = previousCheckpoint.statement?.receipt_digests ?? [];
      const currentDigests = checkpoint.statement?.receipt_digests ?? [];
      for (let digestIndex = 0; digestIndex < priorDigests.length; digestIndex += 1) {
        if (currentDigests[digestIndex] !== priorDigests[digestIndex]) {
          errors.push(`checkpoint ${index}: prior receipt digest ${digestIndex} changed`);
          break;
        }
      }
    }

    previousCheckpoint = checkpoint;
  });

  return { ok: errors.length === 0, errors };
}

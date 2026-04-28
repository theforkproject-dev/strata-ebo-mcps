import { canonicalize } from "./canonicalize.js";
import { sha256Hex } from "./crypto.js";
import { merkleRoot } from "./merkle.js";

export const STREAM_CHUNK_VERSION = "turnstile.stream-chunk.v1";
export const STREAM_COMMITMENT_VERSION = "turnstile.stream-commitment.v1";

export function createStreamChunkDigest({ streamId, index, chunk }) {
  return sha256Hex(canonicalize({
    version: STREAM_CHUNK_VERSION,
    stream_id: streamId,
    index,
    chunk_digest: sha256Hex(canonicalize(chunk))
  }));
}

export function createStreamCommitment({ streamId, chunks = null, chunkDigests = null }) {
  const digests = chunkDigests ?? chunks.map((chunk, index) => createStreamChunkDigest({ streamId, index, chunk }));

  return {
    version: STREAM_COMMITMENT_VERSION,
    stream_id: streamId,
    chunk_count: digests.length,
    chunk_digests: digests,
    partial_merkle_root: merkleRoot(digests)
  };
}

export function verifyStreamCommitment(commitment) {
  const errors = [];

  if (!commitment || commitment.version !== STREAM_COMMITMENT_VERSION) {
    return { ok: false, errors: ["invalid stream commitment version"] };
  }

  if (!commitment.stream_id) {
    errors.push("stream_id is required");
  }

  if (!Array.isArray(commitment.chunk_digests)) {
    errors.push("chunk_digests must be an array");
  } else {
    if (commitment.chunk_count !== commitment.chunk_digests.length) {
      errors.push("chunk_count does not match chunk_digests length");
    }

    for (const [index, digest] of commitment.chunk_digests.entries()) {
      if (typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest)) {
        errors.push(`chunk_digests[${index}] must be a sha256 hex digest`);
      }
    }

    const expectedRoot = merkleRoot(commitment.chunk_digests);
    if (commitment.partial_merkle_root !== expectedRoot) {
      errors.push("partial_merkle_root does not match chunk_digests");
    }
  }

  return { ok: errors.length === 0, errors };
}

import { canonicalize } from "./canonicalize.js";
import { sha256Hex } from "./crypto.js";

export const EMPTY_MERKLE_ROOT = sha256Hex("turnstile-empty-merkle-v1");

export function merkleLeafDigest(value) {
  return sha256Hex(canonicalize({
    protocol: "turnstile-merkle-leaf-v1",
    value
  }));
}

export function merkleParentDigest(left, right) {
  return sha256Hex(canonicalize({
    left,
    protocol: "turnstile-merkle-parent-v1",
    right
  }));
}

export function merkleRoot(leafDigests) {
  if (leafDigests.length === 0) {
    return EMPTY_MERKLE_ROOT;
  }

  let level = [...leafDigests];

  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] ?? left;
      next.push(merkleParentDigest(left, right));
    }
    level = next;
  }

  return level[0];
}

import { createHash, timingSafeEqual } from "node:crypto";

export function verifyPkce({ verifier, challenge, method }) {
  if (!verifier || !challenge || method !== "S256") {
    return false;
  }
  const digest = createHash("sha256").update(verifier).digest("base64url");
  return safeEqual(digest, challenge);
}

export function sha256Hex(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

export function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

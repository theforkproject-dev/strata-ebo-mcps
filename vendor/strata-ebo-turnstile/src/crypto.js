import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify
} from "node:crypto";

export function sha256Hex(value) {
  return createHash("sha256").update(toBuffer(value)).digest("hex");
}

export function base64urlEncode(value) {
  return toBuffer(value).toString("base64url");
}

export function base64urlDecode(value) {
  return Buffer.from(value, "base64url");
}

export function signEd25519(message, privateKey) {
  return base64urlEncode(nodeSign(null, toBuffer(message), normalizePrivateKey(privateKey)));
}

export function verifyEd25519(message, signature, publicKey) {
  return nodeVerify(null, toBuffer(message), normalizePublicKey(publicKey), base64urlDecode(signature));
}

export function keyFingerprint(publicKey) {
  const key = normalizePublicKey(publicKey);
  const der = key.export({ format: "der", type: "spki" });
  return `ed25519:${sha256Hex(der)}`;
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }

  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }

  return Buffer.from(String(value), "utf8");
}

function normalizePrivateKey(privateKey) {
  if (typeof privateKey === "string" || Buffer.isBuffer(privateKey)) {
    return createPrivateKey(privateKey);
  }

  return privateKey;
}

function normalizePublicKey(publicKey) {
  if (typeof publicKey === "string" || Buffer.isBuffer(publicKey)) {
    return createPublicKey(publicKey);
  }

  return publicKey;
}

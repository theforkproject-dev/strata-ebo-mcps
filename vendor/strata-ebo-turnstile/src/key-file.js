import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { createPublicKey, generateKeyPairSync } from "node:crypto";

export function loadOrCreateEd25519Signer({ keyFile, keyId, keyJson = null, privateKeyPem = null, publicKeyPem = null }) {
  if (keyJson) {
    return signerFromSaved(JSON.parse(keyJson), keyId);
  }

  if (privateKeyPem) {
    return signerFromSaved({
      key_id: keyId,
      private_key_pem: privateKeyPem,
      public_key_pem: publicKeyPem
    }, keyId);
  }

  if (keyFile && existsSync(keyFile)) {
    return signerFromSaved(JSON.parse(readFileSync(keyFile, "utf8")), keyId);
  }

  const keys = generateKeyPairSync("ed25519");
  const saved = {
    key_id: keyId,
    private_key_pem: keys.privateKey.export({ type: "pkcs8", format: "pem" }),
    public_key_pem: keys.publicKey.export({ type: "spki", format: "pem" })
  };

  if (keyFile) {
    mkdirSync(dirname(keyFile), { recursive: true });
    writeFileSync(keyFile, `${JSON.stringify(saved, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  }

  return signerFromSaved(saved, keyId);
}

function signerFromSaved(saved, fallbackKeyId) {
  const keyId = saved.key_id ?? fallbackKeyId;
  if (!keyId) {
    throw new Error("Ed25519 key id is required");
  }
  if (!saved.private_key_pem) {
    throw new Error(`Ed25519 private key PEM is required for ${keyId}`);
  }

  const publicKeyPem = saved.public_key_pem ?? createPublicKey(saved.private_key_pem).export({
    type: "spki",
    format: "pem"
  });

  return {
    signer: {
      keyId,
      privateKey: saved.private_key_pem
    },
    publicKeyPem
  };
}

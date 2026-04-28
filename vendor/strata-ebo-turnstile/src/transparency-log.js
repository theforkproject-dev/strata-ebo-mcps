import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { appendFile } from "node:fs/promises";
import { dirname } from "node:path";
import { canonicalize } from "./canonicalize.js";
import { sha256Hex, signEd25519, verifyEd25519 } from "./crypto.js";
import { merkleRoot } from "./merkle.js";

export const TRANSPARENCY_ENTRY_VERSION = "turnstile.transparency-entry.v1";
export const TRANSPARENCY_INCLUSION_VERSION = "turnstile.transparency-inclusion.v1";

export class LocalTransparencyLog {
  constructor({ filePath, signer, logId = "local-transparency-log", clock = () => new Date() }) {
    this.filePath = filePath;
    this.signer = signer;
    this.logId = logId;
    this.clock = clock;
    mkdirSync(dirname(filePath), { recursive: true });
  }

  async append(subject) {
    const entries = this.readAll();
    const payload = {
      version: TRANSPARENCY_ENTRY_VERSION,
      log_id: this.logId,
      entry_index: entries.length,
      prev_entry_hash: entries.at(-1)?.entry_hash ?? "0".repeat(64),
      subject_digest: transparencySubjectDigest(subject),
      subject,
      integrated_at: this.clock().toISOString()
    };
    const entryHash = transparencyEntryHash(payload);
    const entry = {
      ...payload,
      entry_hash: entryHash,
      signature: {
        key_id: this.signer.keyId,
        alg: "Ed25519",
        sig: signEd25519(transparencyEntrySigningMessage(payload), this.signer.privateKey)
      }
    };

    await appendFile(this.filePath, `${canonicalize(entry)}\n`, "utf8");

    return createTransparencyInclusion(entry, [...entries, entry]);
  }

  readAll() {
    let raw;
    try {
      raw = readFileSync(this.filePath, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") {
        return [];
      }
      throw error;
    }

    return raw
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line, index) => {
        try {
          return JSON.parse(line);
        } catch (error) {
          throw new Error(`Invalid transparency entry at line ${index + 1}: ${error.message}`);
        }
      });
  }

  reset() {
    rmSync(this.filePath, { force: true });
  }
}

export function transparencySubjectDigest(subject) {
  return sha256Hex(canonicalize(subject));
}

export function transparencyEntryHash(entryPayload) {
  return sha256Hex(canonicalize({
    protocol: TRANSPARENCY_ENTRY_VERSION,
    entry: entryPayload
  }));
}

export function transparencyEntrySigningMessage(entryPayload) {
  return `${TRANSPARENCY_ENTRY_VERSION}\n${transparencyEntryHash(entryPayload)}`;
}

export function createTransparencyInclusion(entry, entries) {
  return {
    version: TRANSPARENCY_INCLUSION_VERSION,
    log_id: entry.log_id,
    entry_index: entry.entry_index,
    subject_digest: entry.subject_digest,
    entry_hash: entry.entry_hash,
    merkle_root: merkleRoot(entries.slice(0, entry.entry_index + 1).map((item) => item.entry_hash)),
    integrated_at: entry.integrated_at,
    log_signature: entry.signature
  };
}

export function verifyTransparencyInclusion(subject, inclusion, entries, keyring) {
  const errors = [];

  if (!inclusion || inclusion.version !== TRANSPARENCY_INCLUSION_VERSION) {
    return { ok: false, errors: ["invalid transparency inclusion version"] };
  }

  if (!Array.isArray(entries)) {
    return { ok: false, errors: ["transparency log entries missing"] };
  }

  const expectedSubjectDigest = transparencySubjectDigest(subject);
  if (inclusion.subject_digest !== expectedSubjectDigest) {
    errors.push("transparency inclusion subject digest mismatch");
  }

  const entry = entries[inclusion.entry_index];
  if (!entry) {
    errors.push("transparency log entry not found at inclusion index");
    return { ok: false, errors };
  }

  if (entry.log_id !== inclusion.log_id) {
    errors.push("transparency log id mismatch");
  }

  if (entry.subject_digest !== expectedSubjectDigest) {
    errors.push("transparency entry subject digest mismatch");
  }

  if (canonicalize(entry.subject) !== canonicalize(subject)) {
    errors.push("transparency entry subject mismatch");
  }

  const { entry_hash: entryHash, signature, ...payload } = entry;
  const expectedEntryHash = transparencyEntryHash(payload);
  if (entryHash !== expectedEntryHash || inclusion.entry_hash !== expectedEntryHash) {
    errors.push("transparency entry hash mismatch");
  }

  const expectedMerkleRoot = merkleRoot(entries.slice(0, inclusion.entry_index + 1).map((item) => item.entry_hash));
  if (inclusion.merkle_root !== expectedMerkleRoot) {
    errors.push("transparency inclusion Merkle root mismatch");
  }

  const sig = inclusion.log_signature ?? signature;
  const publicKey = sig && keyring[sig.key_id];
  if (!sig || sig.alg !== "Ed25519") {
    errors.push("transparency entry missing Ed25519 signature");
  } else if (!publicKey) {
    errors.push(`unknown transparency log key: ${sig.key_id}`);
  } else if (!verifyEd25519(transparencyEntrySigningMessage(payload), sig.sig, publicKey)) {
    errors.push(`invalid transparency log signature: ${sig.key_id}`);
  }

  return { ok: errors.length === 0, errors };
}

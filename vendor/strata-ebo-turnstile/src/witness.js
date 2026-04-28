import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { canonicalize } from "./canonicalize.js";
import { quorumSubjectDigest, signQuorumSubject } from "./quorum.js";

export class Witness {
  constructor({ id, signer, walPath, clock = () => new Date() }) {
    this.id = id;
    this.keyId = signer.keyId;
    this.privateKey = signer.privateKey;
    this.walPath = walPath;
    this.clock = clock;
    this.signedSubjects = new Map();
    mkdirSync(dirname(walPath), { recursive: true });
    this.loadWal();
  }

  sign(subject) {
    const guardKey = `${subject.domain}:${subject.session_id}:${subject.step_index ?? subject.checkpoint_index ?? "boundary"}`;
    const digest = quorumSubjectDigest(subject);
    const priorDigest = this.signedSubjects.get(guardKey);

    if (priorDigest && priorDigest !== digest) {
      this.appendWal({
        type: "refusal",
        witness_id: this.id,
        guard_key: guardKey,
        existing_subject_digest: priorDigest,
        refused_subject_digest: digest,
        issued_at: this.clock().toISOString()
      });
      throw new Error(`witness ${this.id} refuses equivocation for ${guardKey}`);
    }

    const signature = signQuorumSubject(subject, this);
    this.signedSubjects.set(guardKey, digest);
    this.appendWal({
      type: "signature",
      witness_id: this.id,
      guard_key: guardKey,
      subject_digest: digest,
      signature,
      subject,
      issued_at: this.clock().toISOString()
    });
    return signature;
  }

  loadWal() {
    let raw;
    try {
      raw = readFileSync(this.walPath, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") {
        return;
      }
      throw error;
    }

    for (const line of raw.split("\n")) {
      if (!line.trim()) {
        continue;
      }
      const entry = JSON.parse(line);
      if (entry.type === "signature") {
        this.signedSubjects.set(entry.guard_key, entry.subject_digest);
      }
    }
  }

  appendWal(entry) {
    appendFileSync(this.walPath, `${canonicalize(entry)}\n`, "utf8");
  }
}

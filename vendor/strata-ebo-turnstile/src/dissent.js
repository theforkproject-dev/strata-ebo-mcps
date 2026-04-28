import { canonicalize } from "./canonicalize.js";
import { sha256Hex, signEd25519, verifyEd25519 } from "./crypto.js";

export const DISSENT_NOTICE_VERSION = "turnstile.dissent-notice.v1";

export const DISSENT_CLASSES = Object.freeze({
  CRYPTOGRAPHIC_OBJECTIVE: "cryptographic-objective",
  POLICY_VIOLATION_BONDED: "policy-violation-bonded",
  SEMANTIC_WARNING_ADVISORY: "semantic-warning-advisory"
});

export function dissentSubjectDigest(subject) {
  return sha256Hex(canonicalize(subject));
}

export function dissentSigningMessage(subject) {
  return `${DISSENT_NOTICE_VERSION}\n${dissentSubjectDigest(subject)}`;
}

export function createDissentNotice({
  noticeId,
  sessionId,
  targetReceiptHash,
  targetStepIndex,
  noticeClass,
  claim,
  evidenceRef = null,
  issuedAt = new Date().toISOString()
}, signer) {
  if (!Object.values(DISSENT_CLASSES).includes(noticeClass)) {
    throw new Error(`Unsupported dissent notice class: ${noticeClass}`);
  }

  const subject = {
    domain: DISSENT_NOTICE_VERSION,
    notice_id: noticeId,
    session_id: sessionId,
    target_receipt_hash: targetReceiptHash,
    target_step_index: targetStepIndex,
    notice_class: noticeClass,
    claim,
    evidence_ref: evidenceRef,
    issued_at: issuedAt
  };

  return {
    version: DISSENT_NOTICE_VERSION,
    subject,
    signature: {
      key_id: signer.keyId,
      alg: "Ed25519",
      sig: signEd25519(dissentSigningMessage(subject), signer.privateKey)
    }
  };
}

export function dissentNoticeDigest(notice) {
  return sha256Hex(canonicalize(notice));
}

export function verifyDissentNotice(notice, receipts, keyring, options = {}) {
  const errors = [];
  const warnings = [];

  if (!notice || notice.version !== DISSENT_NOTICE_VERSION) {
    return { ok: false, errors: ["invalid dissent notice version"], warnings };
  }

  const subject = notice.subject;
  if (!subject || subject.domain !== DISSENT_NOTICE_VERSION) {
    errors.push("dissent subject domain mismatch");
  }

  const signature = notice.signature;
  const publicKey = signature && keyring[signature.key_id];
  if (!signature || signature.alg !== "Ed25519") {
    errors.push("dissent notice missing Ed25519 signature");
  } else if (!publicKey) {
    errors.push(`unknown dissent signer key: ${signature.key_id}`);
  } else if (!verifyEd25519(dissentSigningMessage(subject), signature.sig, publicKey)) {
    errors.push(`invalid dissent signature: ${signature.key_id}`);
  }

  const target = receipts.find((receipt) => receipt.state_root === subject?.target_receipt_hash);
  if (!target) {
    errors.push("dissent target receipt not found");
  } else {
    if (target.session_id !== subject.session_id) {
      errors.push("dissent target session mismatch");
    }
    if (target.step_index !== subject.target_step_index) {
      errors.push("dissent target step mismatch");
    }
  }

  if (!Object.values(DISSENT_CLASSES).includes(subject?.notice_class)) {
    errors.push(`unsupported dissent notice class: ${subject?.notice_class}`);
  } else if (subject.notice_class === DISSENT_CLASSES.CRYPTOGRAPHIC_OBJECTIVE) {
    errors.push(`cryptographic dissent notice ${subject.notice_id}: ${subject.claim}`);
  } else if (subject.notice_class === DISSENT_CLASSES.POLICY_VIOLATION_BONDED) {
    const message = `policy dissent notice ${subject.notice_id}: ${subject.claim}`;
    if (options.failOnPolicyDissent) {
      errors.push(message);
    } else {
      warnings.push(message);
    }
  } else {
    warnings.push(`semantic dissent notice ${subject.notice_id}: ${subject.claim}`);
  }

  return { ok: errors.length === 0, errors, warnings };
}

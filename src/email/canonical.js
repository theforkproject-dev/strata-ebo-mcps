import { digestValue, sha256Hex } from "../strata/primitives.js";

export const EMAIL_PAYLOAD_VERSION = "strata.email.payload.v2";
export const EMAIL_COMMITMENT_VERSION = "strata.email.commitment.v2";
export const LEGACY_EMAIL_PAYLOAD_VERSION = "strata.email.payload.v1";
export const LEGACY_EMAIL_COMMITMENT_VERSION = "strata.email.commitment.v1";

export function canonicalizeEmailInput(input, defaults = {}) {
  return canonicalizeEmailInputV2(input, defaults);
}

export function emailCommitment(input, defaults = {}, options = {}) {
  const version = options.commitmentVersion || EMAIL_COMMITMENT_VERSION;
  if (version === LEGACY_EMAIL_COMMITMENT_VERSION) {
    return emailCommitmentV1(input, defaults);
  }
  if (version !== EMAIL_COMMITMENT_VERSION) {
    throw new Error(`Unsupported email commitment version: ${version}`);
  }
  return emailCommitmentV2(input, defaults);
}

function canonicalizeEmailInputV2(input, defaults = {}) {
  const from = normalizeAddress(input.from || defaults.from || "");
  const to = normalizeAddressList(input.to);
  const cc = normalizeAddressList(input.cc);
  const bcc = normalizeAddressList(input.bcc);
  const subject = requireString(input.subject, "subject");
  const text = normalizeBody(input.text);
  const html = normalizeBody(input.html);

  if (!from) {
    throw new Error("from is required. Set EMAIL_FROM or provide from.");
  }
  if (to.length === 0) {
    throw new Error("to must include at least one recipient");
  }
  if (!text && !html) {
    throw new Error("text or html body is required");
  }

  return {
    version: EMAIL_PAYLOAD_VERSION,
    from,
    to,
    cc,
    bcc,
    subject,
    text,
    html,
    reply_to: normalizeAddressList(input.reply_to || input.replyTo),
    tags: normalizeTags(input.tags),
    attachments: normalizeAttachments(input.attachments)
  };
}

function emailCommitmentV2(input, defaults = {}) {
  const canonical = canonicalizeEmailInputV2(input, defaults);
  const attachmentDigests = canonical.attachments.map((attachment) => ({
    filename: attachment.filename,
    content_type: attachment.content_type,
    content_digest: attachment.content_digest,
    size_bytes: attachment.size_bytes
  }));
  const allRecipients = [...canonical.to, ...canonical.cc, ...canonical.bcc];
  const recipientHashes = allRecipients.map((address) => sha256Hex(mailboxOf(address)));
  const recipientDomains = [...new Set(allRecipients.map(domainOf).filter(Boolean))].sort();

  return {
    canonical,
    publicCommitment: {
      version: EMAIL_COMMITMENT_VERSION,
      payload_digest: digestValue(recipientReproduciblePayload(canonical)),
      from_domain: domainOf(canonical.from),
      recipient_count: allRecipients.length,
      recipient_domains: recipientDomains,
      recipient_hashes: recipientHashes,
      subject_digest: sha256Hex(canonical.subject),
      text_digest: canonical.text ? sha256Hex(canonical.text) : null,
      html_digest: canonical.html ? sha256Hex(canonical.html) : null,
      attachment_digests: attachmentDigests,
      audit_tags: canonical.tags,
      audit_tags_digest: digestValue(canonical.tags),
      canonicalization: {
        body_line_endings: "CRLF",
        terminal_body_line_breaks: "stripped",
        payload_digest_excludes: ["audit_tags", "attachment_content_base64"]
      }
    }
  };
}

function emailCommitmentV1(input, defaults = {}) {
  const canonical = canonicalizeEmailInputV1(input, defaults);
  const attachmentDigests = canonical.attachments.map((attachment) => ({
    filename: attachment.filename,
    content_type: attachment.content_type,
    content_digest: attachment.content_digest,
    size_bytes: attachment.size_bytes
  }));
  const allRecipients = [...canonical.to, ...canonical.cc, ...canonical.bcc];
  return {
    canonical,
    publicCommitment: {
      version: LEGACY_EMAIL_COMMITMENT_VERSION,
      payload_digest: digestValue(canonical),
      from_domain: domainOf(canonical.from),
      recipient_count: allRecipients.length,
      recipient_domains: [...new Set(allRecipients.map(domainOf).filter(Boolean))].sort(),
      recipient_hashes: allRecipients.map((address) => sha256Hex(mailboxOf(address))),
      subject_digest: sha256Hex(canonical.subject),
      text_digest: canonical.text ? sha256Hex(canonical.text) : null,
      html_digest: canonical.html ? sha256Hex(canonical.html) : null,
      attachment_digests: attachmentDigests,
      tags: canonical.tags
    }
  };
}

function canonicalizeEmailInputV1(input, defaults = {}) {
  const from = normalizeAddress(input.from || defaults.from || "");
  const to = normalizeAddressList(input.to);
  const cc = normalizeAddressList(input.cc);
  const bcc = normalizeAddressList(input.bcc);
  const subject = requireString(input.subject, "subject");
  const text = optionalString(input.text);
  const html = optionalString(input.html);

  if (!from) {
    throw new Error("from is required. Set EMAIL_FROM or provide from.");
  }
  if (to.length === 0) {
    throw new Error("to must include at least one recipient");
  }
  if (!text && !html) {
    throw new Error("text or html body is required");
  }

  return {
    version: LEGACY_EMAIL_PAYLOAD_VERSION,
    from,
    to,
    cc,
    bcc,
    subject,
    text,
    html,
    reply_to: normalizeAddressList(input.reply_to || input.replyTo),
    tags: normalizeTags(input.tags),
    attachments: normalizeAttachments(input.attachments)
  };
}

function recipientReproduciblePayload(canonical) {
  return {
    version: canonical.version,
    from: canonical.from,
    to: canonical.to,
    cc: canonical.cc,
    bcc: canonical.bcc,
    subject: canonical.subject,
    text: canonical.text,
    html: canonical.html,
    reply_to: canonical.reply_to,
    attachments: canonical.attachments.map((attachment) => ({
      filename: attachment.filename,
      content_type: attachment.content_type,
      content_digest: attachment.content_digest,
      size_bytes: attachment.size_bytes
    }))
  };
}

export function resendPayloadFromCanonical(canonical, headers) {
  return {
    from: canonical.from,
    to: canonical.to,
    ...(canonical.cc.length ? { cc: canonical.cc } : {}),
    ...(canonical.bcc.length ? { bcc: canonical.bcc } : {}),
    ...(canonical.reply_to.length ? { reply_to: canonical.reply_to } : {}),
    subject: canonical.subject,
    ...(canonical.text ? { text: canonical.text } : {}),
    ...(canonical.html ? { html: canonical.html } : {}),
    ...(canonical.attachments.length ? {
      attachments: canonical.attachments.map((attachment) => ({
        filename: attachment.filename,
        content: attachment.content_base64,
        ...(attachment.content_type ? { content_type: attachment.content_type } : {})
      }))
    } : {}),
    headers
  };
}

export function redactCanonical(canonical) {
  const { publicCommitment } = emailCommitment(canonical);
  return publicCommitment;
}

function normalizeAddressList(value) {
  if (!value) {
    return [];
  }
  const raw = Array.isArray(value) ? value : [value];
  return raw.map(normalizeAddress).filter(Boolean);
}

function normalizeAddress(address) {
  if (!address) {
    return "";
  }
  const trimmed = String(address).trim();
  const displayMatch = trimmed.match(/^(.*?)<([^<>]+)>$/);
  if (displayMatch) {
    const display = displayMatch[1].trim();
    const mailbox = normalizeMailbox(displayMatch[2]);
    return display ? `${display} <${mailbox}>` : mailbox;
  }
  return normalizeMailbox(trimmed);
}

function normalizeMailbox(mailbox) {
  const trimmed = String(mailbox).trim();
  const at = trimmed.lastIndexOf("@");
  if (at === -1) {
    return trimmed;
  }
  return `${trimmed.slice(0, at)}@${trimmed.slice(at + 1).toLowerCase()}`;
}

function domainOf(address) {
  const mailbox = mailboxOf(address);
  const at = mailbox.lastIndexOf("@");
  return at === -1 ? null : mailbox.slice(at + 1).toLowerCase();
}

function mailboxOf(address) {
  const value = String(address).trim();
  const displayMatch = value.match(/<([^<>]+)>$/);
  return displayMatch ? displayMatch[1].trim() : value;
}

function requireString(value, field) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${field} is required`);
  }
  return value;
}

function optionalString(value) {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function normalizeBody(value) {
  if (typeof value !== "string" || value.length === 0) {
    return null;
  }
  return value
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(/\n+$/g, "")
    .replace(/\n/g, "\r\n");
}

function normalizeTags(tags) {
  if (!tags || typeof tags !== "object" || Array.isArray(tags)) {
    return {};
  }
  return Object.fromEntries(Object.entries(tags).map(([key, value]) => [String(key), String(value)]).sort(([a], [b]) => a.localeCompare(b)));
}

function normalizeAttachments(attachments) {
  if (!attachments) {
    return [];
  }
  if (!Array.isArray(attachments)) {
    throw new Error("attachments must be an array");
  }
  return attachments.map((attachment, index) => {
    if (!attachment || typeof attachment !== "object") {
      throw new Error(`attachments[${index}] must be an object`);
    }
    const filename = requireString(attachment.filename, `attachments[${index}].filename`);
    const contentBase64 = requireString(attachment.content_base64 || attachment.contentBase64, `attachments[${index}].content_base64`);
    const bytes = Buffer.from(contentBase64, "base64");
    return {
      filename,
      content_type: optionalString(attachment.content_type || attachment.contentType),
      content_base64: contentBase64,
      content_digest: sha256Hex(bytes),
      size_bytes: bytes.length
    };
  }).sort((a, b) => a.filename.localeCompare(b.filename));
}

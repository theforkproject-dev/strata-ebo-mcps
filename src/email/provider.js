import { emailCommitment, resendPayloadFromCanonical } from "./canonical.js";

export function createEmailProvider(config) {
  if (config.provider === "dry-run") {
    return createDryRunProvider();
  }
  if (config.provider === "resend") {
    return createResendProvider(config);
  }
  throw new Error(`Unsupported EMAIL_PROVIDER: ${config.provider}`);
}

function createDryRunProvider() {
  return {
    name: "dry-run",
    async send({ canonical, headers }) {
      const { publicCommitment } = emailCommitment(canonical);
      return {
        provider: "dry-run",
        status: "accepted",
        message_id: `dry_${publicCommitment.payload_digest.slice(0, 24)}`,
        sent_at: new Date().toISOString(),
        headers_committed: headers
      };
    }
  };
}

function createResendProvider(config) {
  if (!config.resendApiKey) {
    throw new Error("RESEND_API_KEY is required when EMAIL_PROVIDER=resend");
  }
  return {
    name: "resend",
    async send({ canonical, headers }) {
      const response = await fetch(`${config.resendBaseUrl}/emails`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${config.resendApiKey}`,
          "content-type": "application/json"
        },
        body: JSON.stringify(resendPayloadFromCanonical(canonical, headers))
      });
      const body = await readJson(response);
      if (!response.ok) {
        throw new Error(`Resend send failed (${response.status}): ${JSON.stringify(body)}`);
      }
      return {
        provider: "resend",
        status: "accepted",
        message_id: body.id,
        sent_at: new Date().toISOString(),
        headers_committed: headers,
        provider_response: {
          id: body.id
        }
      };
    }
  };
}

async function readJson(response) {
  const text = await response.text();
  if (!text) {
    return {};
  }
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

# Strata Email MCP Demo

This project demonstrates an MCP server whose ordinary email capability is gated by the Strata Verified Action Gateway.

Core claim:

> Any MCP-speaking agent can discover an email sending capability, call it like a normal MCP tool, and receive both a normal email result and a verifiable Strata certificate showing the send action passed through Level 1 mechanical witnesses and Level 2 policy witnesses.

## What This Shows

- Developers see a normal MCP surface: `initialize`, `tools/list`, `tools/call`, `resources/list`, and `resources/read`.
- Observers see a consequential external action: outbound email through a real provider.
- The send path is gated by Strata: capability token, witnessed `IntentGrant`, signed tool execution receipt, witnessed observation, checkpoint, and verifier output.
- Certificate artifacts are digest-first: raw email content is not persisted by default.
- A recipient-side verification tool can create a signed verification receipt after comparing a received email payload to the certified digest.

## Tools

- `email_preview`: Canonicalizes an email and returns payload digests without sending.
- `email_send_verified`: Sends an email through the Strata gateway and returns provider metadata plus certificate refs.
- `email_verify_received`: Verifies a received email against a certificate and writes a recipient verification receipt.
- `gateway_status`: Checks email provider configuration, witness health, quorum availability, and certificate transmission fields.

`email_send_verified` requires both L1 mechanical quorum and L2 policy quorum. The default L2 policy allows sends only when sender domain is `theforkproject.com`, every recipient domain is `amotivv.com`, recipient count is at most 3, subject starts with `[Verified]`, body/subject do not contain denied keywords, and tags include `conversation_id` and `turn_id`.

`email_verify_received.received` is a typed object matching the email fields from preview/send. It also accepts optional `headers`, including `X-Strata-Action-Id`, `X-Strata-Payload-Digest`, `X-Strata-Certificate-URL`, and `X-Strata-Witness-Tier` when the mail client/API exposes them. Some APIs hide custom headers; verification still works from the received canonical content plus certificate ref, but supplied headers are checked against the certificate.

## Resources

- `strata://action-registry/current`: MCP projection of available actions and assurance requirements.
- `strata://certificate/latest`: Latest verified email certificate metadata.
- `strata://recipient-verification/latest`: Latest recipient verification receipt, if one exists.

## Local Demo Without Sending

```bash
npm run demo:dry-run
```

The demo starts three non-TEE local L1 HTTP witness servers and three local L2 policy witness servers, starts this MCP server, performs an L2-denied send attempt, performs a successful verified send, and writes artifacts under `artifacts/email-mcp/`.

## Real Resend Send

Create `.env` from `.env.example`, set:

```ini
EMAIL_PROVIDER=resend
RESEND_API_KEY=...
EMAIL_FROM="strata-mcp@theforkproject.com"
```

Then run:

```bash
npm start
```

For real sends, provide three Level 1 witness URLs in `WITNESS_URLS` and three Level 2 policy witness URLs in `POLICY_WITNESS_URLS`, or use the local demo runner as the process supervisor while setting Resend credentials.

The first real recipient for the demo can be passed as the MCP tool argument:

```json
{
  "to": ["jason@amotivv.com"],
  "subject": "Verified agent email demo",
  "text": "This email was routed through the Strata Verified Action Gateway."
}
```

## OAuth Connector Support

Set `OAUTH_ISSUER` and one consent secret to enable OAuth 2.1 connector mode:

```ini
OAUTH_ISSUER=https://strata-email-mcp.fly.dev
OAUTH_CONSENT_PASSWORD=...
```

Implemented endpoints:

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-authorization-server`
- `/oauth/register`
- `/oauth/authorize`
- `/oauth/token`
- `/oauth/revoke`

The flow supports Dynamic Client Registration, PKCE S256 authorization code exchange, refresh token rotation, and MCP bearer-token validation.

OAuth clients, authorization codes, access tokens, and refresh tokens are persisted to `OAUTH_STORE_PATH`. On Fly this is `/data/email-mcp/oauth-store.json` on the mounted MCP volume.

Current limitation: the file store is appropriate for one MCP machine. If the app scales horizontally, replace it with a shared database-backed store.

## Fly.io

Fly.io is the recommended host for the live demo. Use one MCP app, three L1 witness apps, and three L2 policy witness apps. See `docs/fly-deployment.md` and `deploy/fly/*.toml.example`.

I do not recommend Netlify for the MCP server itself. Netlify can host a static explainer or certificate viewer, but the MCP server needs long-lived HTTP behavior, persistent artifacts/keys, and separately addressable witness servers.

## Artifact Privacy

The certificate does not store raw subject/body/attachment bytes. It stores:

- canonical payload digest
- subject/body/attachment digests
- recipient hashes and recipient domains
- provider message ID and send timestamp
- Strata receipt/checkpoint/transparency refs
- verifier result and witness quorum metadata

This is the realistic default for business email: the counterparty can verify content possession by recomputing the digest from the received message, while the public/audit artifact avoids unnecessary content disclosure.

## Certificate Timing And Transmission

`email_preview` returns the canonical digest commitment only. No certificate exists yet because no witnessed side effect has occurred.

`email_send_verified` creates the certificate after the gateway mints a capability, obtains witness quorum, the email adapter sends via Resend, and verification succeeds.

Agents can inspect `gateway_status.protocol.commitment_schema_version` before sending. The current commitment schema is `strata.email.commitment.v2`.

`strata.email.commitment.v2` normalizes text/html body line endings to CRLF and strips terminal body line breaks before hashing, so send-side and recipient-side digests survive SMTP transit normalization. The recipient-reproducible payload digest excludes sender-only audit tags and raw attachment base64; tags are preserved as `audit_tags` plus `audit_tags_digest` in the public commitment.

The certificate reference is transmitted two ways:

- In-band email headers: `X-Strata-Action-Id`, `X-Strata-Payload-Digest`, `X-Strata-Certificate-URL`, `X-Strata-Witness-Tier`.
- MCP result fields: `certificate_url`, `certificate_digest`, `payload_digest`, `receipt_root`, `checkpoint_id`.

Tags are intentionally flat `Record<string,string>` for MCP schema compatibility. Use flattened conventions like `conversation_id`, `turn_id`, `skill_name`, or `case_id`; nested provenance can be added later if needed.

## Receipt Count And Action Grant Semantics

`receipt_count` counts hash-chained protocol receipts, not witnesses. A successful verified email send currently produces six receipts:

1. `session.start`
2. `tool.request`
3. `intent.grant`
4. `tool.execution`
5. `observation`
6. `session.end`

The 2-of-3 Level 1 witness quorum is embedded in quorum certificates on selected receipts. It is not represented as one receipt per witness. The 2-of-3 Level 2 policy quorum is captured as signed policy decisions and embedded into the `IntentGrant` as a typed input edge.

L2 policy signatures do not add new receipt phases. They are collected before `intent.grant`, persisted in `policy-decision.json`, and their decision digests are embedded into `intent.grant.body.intent.intended_action.typed_inputs`.

`X-Strata-Action-Id` is the pre-send `IntentGrant` `grant_id`. It means the gateway first granted a single-use capability for this exact canonical email payload, then the adapter executed the send and signed provider metadata.

## Current Scope

This version uses operator-controlled non-TEE Level 1 HTTP witnesses and Level 2 policy witnesses. It demonstrates the L1/L2 protocol shape, but not independent witness operators, L3 domain attestors, or TEE substrate attestation.

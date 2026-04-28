# Architecture

The server combines two existing patterns:

- Memory Box Go's MCP shape: hand-rolled HTTP JSON-RPC, `MCP-Session-Id`, tool dispatch, tool-level `isError` failures, and resources.
- Strata TURNSTILE's verified action shape: `ActionGateway`, capability token, witnessed `IntentGrant`, signed tool execution receipt, witnessed observation, checkpoint, and verifier output.

## Flow

1. MCP client calls `tools/list` and discovers `gateway_status` and `email_send_verified`.
2. MCP client may call `gateway_status` to check provider configuration and witness quorum availability.
3. MCP client calls `email_send_verified` with recipient, subject, text/html, and optional tags.
4. The server canonicalizes the email into a digest-first payload commitment.
5. `ActionGateway.toolCall()` mints a single-use capability and asks three Level 1 witnesses for quorum over the `IntentGrant`.
6. The email adapter verifies the capability, sends through Resend, and signs a `tool.execution` receipt.
7. The gateway appends a witnessed observation and session end receipt.
8. The server writes a checkpoint, verifies the resulting chain, and returns MCP structured content with provider metadata and certificate refs.

## Recipient Verification

`email_verify_received` models the downstream verification loop. A recipient or recipient-side agent provides the received canonical email fields plus a certificate ref. The tool recomputes the digest, verifies the Strata receipt chain/checkpoint, compares the payload digest, and writes a signed verification receipt.

This is not a classic read receipt. It says: this received email payload matches a certified agent action and the certificate verifies under the declared Level 1 witness policy.

## Certificate Channel

No certificate exists at preview time. Preview only returns a digest commitment. The certificate is produced only after `email_send_verified` performs the witnessed side effect.

The email adapter commits the certificate reference into the outbound message using headers:

- `X-Strata-Action-Id`
- `X-Strata-Payload-Digest`
- `X-Strata-Certificate-URL`
- `X-Strata-Witness-Tier`

The same metadata is returned in the MCP tool result, so an agent can show the sender the certificate immediately while a recipient-side verifier can extract the header from the received message.

`email_verify_received` accepts the received canonical email fields as a typed object. It also accepts optional `headers` for recipient clients that can access custom mail headers. If `X-Strata-*` headers are supplied, the verifier checks them against the certificate metadata; if they are absent, content/certificate verification still proceeds because some mail APIs hide custom headers.

`gateway_status` exposes protocol/schema versions, including `commitment_schema_version`, so agents can detect the expected canonicalization contract before producing or comparing digests.

`strata.email.commitment.v2` is transit-aware: text/html line endings are canonicalized to CRLF and terminal body line breaks are stripped before hashing. Sender-only `audit_tags` are not part of the recipient-reproducible payload digest, so recipients do not need private sender provenance metadata to verify content.

## Receipt Flow

`receipt_count` counts protocol receipts in the hash chain. It is not the number of witnesses. A successful verified email send currently has six receipts:

1. `session.start` opens the certified session and binds policy/admission evidence.
2. `tool.request` commits to the requested email send digest.
3. `intent.grant` records the gateway's single-use capability grant; Level 1 witnesses sign this grant subject.
4. `tool.execution` records the email adapter's signed execution and provider message metadata.
5. `observation` records the gateway's observation of the execution output digest; Level 1 witnesses sign this observation subject.
6. `session.end` closes the certified session.

The header `X-Strata-Action-Id` carries the pre-send `IntentGrant` `grant_id`, so the action is auditable as: the agent was granted permission to perform this exact side effect, then the side effect occurred under that grant.

Tags are flat strings by design for MCP compatibility. Use naming conventions such as `conversation_id`, `turn_id`, `skill_name`, and `case_id` for hierarchical provenance until nested tags are needed.

## OAuth Connector Layer

When `OAUTH_ISSUER` is set, the server exposes OAuth 2.1 metadata, Dynamic Client Registration, PKCE S256 authorization code flow, refresh tokens, revocation, and bearer-token validation for `/mcp`.

This follows the same broad MCP connector pattern as Memory Box Go: OAuth handles client authorization; MCP sessions use `MCP-Session-Id`; JSON-RPC errors are reserved for protocol failures; tool-level failures are returned as successful JSON-RPC responses with `isError: true`.

OAuth state is persisted to `OAUTH_STORE_PATH` as JSON. This keeps Claude connector registrations and refresh tokens across a single-machine Fly restart. It is not a replacement for a shared database if the MCP app runs multiple machines.

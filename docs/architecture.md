# Architecture

The server combines two existing patterns:

- Memory Box Go's MCP shape: hand-rolled HTTP JSON-RPC, `MCP-Session-Id`, tool dispatch, tool-level `isError` failures, and resources.
- Strata TURNSTILE's verified action shape: `ActionGateway`, capability token, witnessed `IntentGrant`, signed tool execution receipt, witnessed observation, checkpoint, and verifier output.

## Flow

1. MCP client calls `tools/list` and discovers `gateway_status` and `email_send_verified`.
2. MCP client may call `gateway_status` to check provider configuration and witness quorum availability.
3. MCP client calls `email_send_verified` with recipient, subject, text/html, and required policy tags.
4. The server canonicalizes the email into a digest-first payload commitment.
5. Three Level 2 policy witnesses evaluate the canonical email against the active policy bundle and return signed allow/deny decisions.
6. The gateway creates an operator-signed admission manifest for tenant `default`, binding the active policy digest, policy URL, allowed action surface, and OAuth/MCP tenant context into `session.start`.
7. `ActionGateway.toolCall()` mints a single-use capability and asks three Level 1 witnesses for quorum over the `IntentGrant`; the L2 policy quorum is embedded as typed input to the grant.
8. The email adapter verifies the capability, sends through Resend, and signs a `tool.execution` receipt.
9. The gateway appends a witnessed observation and session end receipt.
10. The server writes a checkpoint, verifies the resulting chain, and returns MCP structured content with provider metadata and certificate refs.

## L2 Policy Witnesses

The functional L2 demo uses three policy witness HTTP services. Each exposes `/health`, `/v1/public-key`, `/v1/policy`, and `/v1/evaluate`.

The active policy bundle is `strata.email.policy_bundle.v1` / `email-policy-epoch-001`. The canonical demo artifact is `policies/email-policy-epoch-001.json`, and the registry publishes it at `/policies/epochs/email-policy-epoch-001`. It requires:

- sender domain `theforkproject.com`
- recipient domains limited to `amotivv.com`
- at most 3 recipients
- subject prefix `[Verified]`
- no denied keywords: `password`, `secret key`, `wire transfer`
- tags `conversation_id` and `turn_id`

Each policy witness signs a `strata.email.policy_decision.v1` allow or deny decision over the exact commitment digest, policy epoch, policy digest, and policy URL. The gateway requires 2-of-3 allow decisions before it asks the L1 gateway witnesses to sign the `IntentGrant`.

## Registry

The demo registry is a separate service from the MCP gateway. It exposes:

- `GET /health`
- `GET /registry/public-key`
- `GET /registry/current`
- `GET /registry/epochs/email-demo-epoch-001`
- `GET /policies/current`
- `GET /policies/epochs/email-policy-epoch-001`
- `GET /operators/current`
- `GET /operators/operator:amotivv-demo`

The registry signs a `turnstile.witness-registry-epoch.v1` object authorizing the six witness keys for workflow `email.send` and the active policy bundle digest. It also publishes a signed `strata.email.policy_pointer.v1` current-policy pointer and signed `strata.operator_registry_record.v1` records that bind operator ids to admission signing keys. Certificates include the registry epoch id, digest, URL, authority key id, policy digest, policy URL, and operator registry binding. Certificate bundles include `registry_epoch.json`, `policy_bundle.json`, and `operator-registry.json` so downstream verifiers can check witness authority, policy-digest binding, and operator key authority at signing time.

## Operator Admission

Each send or policy-denied attempt creates a signed `turnstile.admission-manifest.v1` for the active tenant. The manifest is signed by the operator key `operator-admission:amotivv-demo` using `strata.operator_admission_signature.v1`. The signed manifest binds:

- tenant id and operator id
- active policy digest and registry-hosted policy URL
- approved MCP/action surface for `email.send`
- configured L1/L2 witness set id and threshold
- OAuth/MCP auth context without storing bearer tokens

The `session.start` receipt commits to the signed admission manifest digest through the existing TURNSTILE `admission_manifest_hash`. Certificates include the admission binding and expose `admission-manifest.json` plus `operator-registry.json` as public artifacts so verifiers can check operator signature, manifest digest binding, policy digest binding, and registry-authorized operator identity.

## Recipient Verification

`email_verify_received` models the downstream verification loop. A recipient or recipient-side agent provides the received canonical email fields plus a certificate ref. The tool recomputes the digest, verifies the Strata receipt chain/checkpoint, compares the payload digest, and writes a signed verification receipt.

This is not a classic read receipt. It says: this received email payload matches a certified agent action and the certificate verifies under the declared L1 mechanical and L2 policy witness requirements.

## Certificate Channel

No certificate exists at preview time. Preview only returns a digest commitment. The certificate is produced only after `email_send_verified` performs the witnessed side effect.

The email adapter commits the certificate reference into the outbound message using headers:

- `X-Strata-Action-Id`
- `X-Strata-Payload-Digest`
- `X-Strata-Certificate-URL`
- `X-Strata-Witness-Tier`

The same metadata is returned in the MCP tool result, so an agent can show the sender the certificate immediately while a recipient-side verifier can extract the header from the received message.

The public certificate endpoint exposes both the certificate summary and a complete verifier-ready bundle:

- `GET /certificates/:id` returns `certificate.json`.
- `GET /certificates/:id/bundle` returns certificate, receipt log, keyring, checkpoint, transparency log, verification result, admission manifest, operator registry record, policy decision, policy bundle, and matching recipient verification receipts.
- The bundle also contains the signed registry epoch used to authorize witness keys at signing time.
- `GET /certificates/:id/artifacts/:name` exposes individual artifacts for tooling that wants streaming or partial retrieval.

`email_verify_received` accepts the received canonical email fields as a typed object. It also accepts optional `headers` for recipient clients that can access custom mail headers. If `X-Strata-*` headers are supplied, the verifier checks them against the certificate metadata; if they are absent, content/certificate verification still proceeds because some mail APIs hide custom headers.

`gateway_status` exposes protocol/schema versions, including `commitment_schema_version`, so agents can detect the expected canonicalization contract before producing or comparing digests.

`strata.email.commitment.v2` is transit-aware: text/html line endings are canonicalized to CRLF and terminal body line breaks are stripped before hashing. Sender-only `audit_tags` are not part of the recipient-reproducible payload digest, so recipients do not need private sender provenance metadata to verify content.

## Receipt Flow

`receipt_count` counts protocol receipts in the hash chain. It is not the number of witnesses. A successful verified email send currently has six receipts:

1. `session.start` opens the certified session and binds policy/admission evidence.
2. `tool.request` commits to the requested email send digest.
3. `intent.grant` records the gateway's single-use capability grant; Level 1 witnesses sign this grant subject, and the grant typed inputs embed the Level 2 policy quorum digest set.
4. `tool.execution` records the email adapter's signed execution and provider message metadata.
5. `observation` records the gateway's observation of the execution output digest; Level 1 witnesses sign this observation subject.
6. `session.end` closes the certified session.

The header `X-Strata-Action-Id` carries the pre-send `IntentGrant` `grant_id`, so the action is auditable as: the agent was granted permission to perform this exact side effect, then the side effect occurred under that grant.

L2 policy signatures do not add new receipt phases. They are collected before `intent.grant`, persisted in `policy-decision.json`, and their decision digests are embedded into the `intent.grant` typed input edge. This keeps `receipt_count` at 6 while making the capability grant commit to the L2 policy quorum.

Denied attempts use a separate auditable certificate path. Because no side effect is authorized, the denial path has no `IntentGrant`, capability token, `tool.execution`, or observation. It produces:

1. `session.start`
2. `policy.request`
3. `policy.decision`
4. `session.end(policy_denied)`

The denial certificate includes the signed L2 policy decisions, checkpoint, transparency log inclusion, and denial reasons. This lets auditors inspect refusal history without relying on operator-local logs.

Tags are flat strings by design for MCP compatibility. Use naming conventions such as `conversation_id`, `turn_id`, `skill_name`, and `case_id` for hierarchical provenance until nested tags are needed.

## OAuth Connector Layer

When `OAUTH_ISSUER` is set, the server exposes OAuth 2.1 metadata, Dynamic Client Registration, PKCE S256 authorization code flow, refresh tokens, revocation, and bearer-token validation for `/mcp`.

This follows the same broad MCP connector pattern as Memory Box Go: OAuth handles client authorization; MCP sessions use `MCP-Session-Id`; JSON-RPC errors are reserved for protocol failures; tool-level failures are returned as successful JSON-RPC responses with `isError: true`.

OAuth state is persisted to `OAUTH_STORE_PATH` as JSON. This keeps Claude connector registrations and refresh tokens across a single-machine Fly restart. It is not a replacement for a shared database if the MCP app runs multiple machines.

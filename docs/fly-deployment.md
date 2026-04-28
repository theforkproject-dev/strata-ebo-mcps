# Fly.io Deployment

Fly.io is the recommended demo host for this project. It can run the long-lived MCP HTTP server, expose stable HTTPS OAuth metadata and certificate URLs, and run independent non-TEE L1 and L2 witness servers.

Netlify is still useful for a static marketing page or certificate viewer, but it is not the right primary host for the MCP server or witness servers.

## App Shape

Use eight Fly apps:

- `strata-email-mcp`: MCP/OAuth/email gateway server.
- `strata-email-witness-1`: Level 1 witness `w1`.
- `strata-email-witness-2`: Level 1 witness `w2`.
- `strata-email-witness-3`: Level 1 witness `w3`.
- `strata-email-policy-witness-1`: Level 2 policy witness `p1`.
- `strata-email-policy-witness-2`: Level 2 policy witness `p2`.
- `strata-email-policy-witness-3`: Level 2 policy witness `p3`.
- `strata-email-registry`: signed witness registry epoch service and governance-hosted policy bundle publisher.

Each app should have one persistent volume:

- MCP volume stores certificates, gateway key material, operator admission signing key material, and recipient verification receipts.
- L1 witness volumes store each witness key and WAL.
- L2 policy witness volumes store each policy witness key.
- Registry volume stores the registry authority signing key.
- The active policy bundle is copied into the image under `policies/email-policy-epoch-001.json`; the registry publishes it at `/policies/epochs/email-policy-epoch-001`.

## Safety

Do not run deployment commands against existing production Fly apps. Use the explicit app names above or adjust them before running.

Before creating or deploying anything, inspect the current Fly account:

```bash
fly auth whoami
fly apps list
```

## Configuration Files

Examples live in `deploy/fly/`:

- `fly.mcp.toml.example`
- `fly.witness-1.toml.example`
- `fly.witness-2.toml.example`
- `fly.witness-3.toml.example`
- `fly.policy-witness-1.toml.example`
- `fly.policy-witness-2.toml.example`
- `fly.policy-witness-3.toml.example`
- `fly.registry.toml.example`

Copy each to a real `fly.*.toml`, review app names, then deploy explicitly with `--config`.

## Secrets

Set secrets only on the MCP app:

```bash
fly secrets set --app strata-email-mcp RESEND_API_KEY=...
fly secrets set --app strata-email-mcp MCP_SESSION_SECRET=...
fly secrets set --app strata-email-mcp OAUTH_CONSENT_PASSWORD=...
```

Use `OAUTH_CONSENT_PASSWORD_SHA256` instead of `OAUTH_CONSENT_PASSWORD` if you do not want the plaintext passphrase in Fly secrets.

The operator admission signing key defaults to `/data/email-mcp/keys/operator-admission.key.json` on the MCP volume. `OPERATOR_ADMISSION_KEY_ID` is a public key identifier; the private key stays on the volume.

## Deployment Order

1. Create/deploy `strata-email-witness-1`, `strata-email-witness-2`, `strata-email-witness-3`.
2. Create/deploy `strata-email-policy-witness-1`, `strata-email-policy-witness-2`, `strata-email-policy-witness-3`.
3. Create/deploy `strata-email-registry` with `WITNESS_URLS` and `POLICY_WITNESS_URLS` pointing at the six witness apps.
4. Confirm each L1 witness returns `/health` and `/v1/public-key`.
5. Confirm each L2 policy witness returns `/health`, `/v1/public-key`, and `/v1/policy`.
6. Confirm registry returns `/registry/current`, `/registry/public-key`, `/policies/current`, `/policies/epochs/email-policy-epoch-001`, `/operators/current`, and `/operators/operator:amotivv-demo`.
7. Deploy `strata-email-mcp` with `WITNESS_URLS`, `POLICY_WITNESS_URLS`, `REGISTRY_URL`, `POLICY_BUNDLE_URL`, `TENANT_ID`, `OPERATOR_ID`, and `OPERATOR_ADMISSION_KEY_ID`.
8. Confirm MCP health and OAuth metadata:

```bash
curl https://strata-email-mcp.fly.dev/health
curl https://strata-email-mcp.fly.dev/.well-known/oauth-protected-resource
curl https://strata-email-mcp.fly.dev/.well-known/oauth-authorization-server
```

Policy endpoint checks:

```bash
curl https://strata-email-registry.fly.dev/policies/current
curl https://strata-email-registry.fly.dev/policies/epochs/email-policy-epoch-001
curl https://strata-email-registry.fly.dev/operators/current
```

`OPERATOR_ADMISSION_PUBLIC_KEY_PEM_BASE64` on the registry app must be the base64-encoded public key PEM for the MCP app's operator admission key. The MCP app owns the private key; the registry publishes the authorized public key mapping.

## Known Demo Tradeoffs

- OAuth clients/tokens are persisted to `/data/email-mcp/oauth-store.json` on the MCP app volume.
- The OAuth file store is intended for one MCP machine. If the app scales horizontally, replace it with a shared database-backed store.
- The Dockerfile uses a vendored copy of the Strata TURNSTILE source under `vendor/strata-ebo-turnstile` so the Fly builder does not need GitHub credentials.

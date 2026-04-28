# Fly.io Deployment

Fly.io is the recommended demo host for this project. It can run the long-lived MCP HTTP server, expose stable HTTPS OAuth metadata and certificate URLs, and run independent non-TEE L1 and L2 witness servers.

Netlify is still useful for a static marketing page or certificate viewer, but it is not the right primary host for the MCP server or witness servers.

## App Shape

Use seven Fly apps:

- `strata-email-mcp`: MCP/OAuth/email gateway server.
- `strata-email-witness-1`: Level 1 witness `w1`.
- `strata-email-witness-2`: Level 1 witness `w2`.
- `strata-email-witness-3`: Level 1 witness `w3`.
- `strata-email-policy-witness-1`: Level 2 policy witness `p1`.
- `strata-email-policy-witness-2`: Level 2 policy witness `p2`.
- `strata-email-policy-witness-3`: Level 2 policy witness `p3`.

Each app should have one persistent volume:

- MCP volume stores certificates, key material, and recipient verification receipts.
- L1 witness volumes store each witness key and WAL.
- L2 policy witness volumes store each policy witness key.

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

Copy each to a real `fly.*.toml`, review app names, then deploy explicitly with `--config`.

## Secrets

Set secrets only on the MCP app:

```bash
fly secrets set --app strata-email-mcp RESEND_API_KEY=...
fly secrets set --app strata-email-mcp MCP_SESSION_SECRET=...
fly secrets set --app strata-email-mcp OAUTH_CONSENT_PASSWORD=...
```

Use `OAUTH_CONSENT_PASSWORD_SHA256` instead of `OAUTH_CONSENT_PASSWORD` if you do not want the plaintext passphrase in Fly secrets.

## Deployment Order

1. Create/deploy `strata-email-witness-1`, `strata-email-witness-2`, `strata-email-witness-3`.
2. Create/deploy `strata-email-policy-witness-1`, `strata-email-policy-witness-2`, `strata-email-policy-witness-3`.
3. Confirm each L1 witness returns `/health` and `/v1/public-key`.
4. Confirm each L2 policy witness returns `/health`, `/v1/public-key`, and `/v1/policy`.
5. Deploy `strata-email-mcp` with `WITNESS_URLS` and `POLICY_WITNESS_URLS` pointing at the six witness apps.
6. Confirm MCP health and OAuth metadata:

```bash
curl https://strata-email-mcp.fly.dev/health
curl https://strata-email-mcp.fly.dev/.well-known/oauth-protected-resource
curl https://strata-email-mcp.fly.dev/.well-known/oauth-authorization-server
```

## Known Demo Tradeoffs

- OAuth clients/tokens are persisted to `/data/email-mcp/oauth-store.json` on the MCP app volume.
- The OAuth file store is intended for one MCP machine. If the app scales horizontally, replace it with a shared database-backed store.
- The Dockerfile uses a vendored copy of the Strata TURNSTILE source under `vendor/strata-ebo-turnstile` so the Fly builder does not need GitHub credentials.

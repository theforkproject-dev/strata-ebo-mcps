# Per-user Google gateways

`gmail`, `gdrive`, and `gcalendar` use the same tenant-bound Nango client and
authenticated connection-control implementation in `src/google/`. Google OAuth
app identity is owned centrally by amotivv; every tenant/service has an explicit
Nango integration and each user grants access separately.

## Settings

- `GATEWAY_KIND`: `gmail`, `gdrive`, or `gcalendar`.
- `GOOGLE_CONNECTOR_ORG_ID`: exact AA Witness organization ID.
- `NANGO_SECRET_KEY`: backend environment key (never agent-facing).
- `NANGO_GMAIL_INTEGRATION_ID`, `NANGO_GDRIVE_INTEGRATION_ID`, or
  `NANGO_GCALENDAR_INTEGRATION_ID`: the exact service/tenant integration.
- `OAUTH_CONSENT_PASSWORD` (or configured hash): also authenticates AA's
  server-side connection-control requests; use a separate secret per gateway.
- Existing stable `MCP_SESSION_SECRET`, OAuth issuer/store, and persistent volume.
- `GOOGLE_OAUTH_TESTING=true`: marks the central flow's seven-day pilot limitation.
- Optional `GOOGLE_CONNECTOR_PILOT_SUBJECTS`: comma-separated full AA subjects.
  With a pilot list, non-pilot users can only use existing grants on the explicit
  `NANGO_GMAIL_LEGACY_INTEGRATION_ID` / `NANGO_GDRIVE_LEGACY_INTEGRATION_ID`.
  Legacy configuration without a pilot list is not ready. Clear both legacy
  settings and the cohort restriction only when moving the whole tenant.

There is no organization-demo fallback for personal Google data. New connection
records require both owner and org tags. Legacy compatibility is restricted to
the explicitly selected legacy integration, with agreement between any owner
representations. A missing or revoked central grant never chooses legacy.

## Control API

Both endpoints require `Authorization: Bearer <gateway-consent-password>`:

- `GET /connectors/nango/<kind>/status?end_user_id=aa:<org>:usr_<id>` returns
  safe readiness, actual account email when available, pilot eligibility and
  Testing status. It does not return a Nango connection ID or token.
- `POST /connectors/nango/<kind>/session` accepts the trusted AA backend's
  subject/email/display name and returns a short-lived Nango Connect link.
  A reconnect selects the exact existing connection after an ownership check.

Browser requests go through AA's authenticated POST endpoint. The old public
`/start` route is not used. Short-lived links and ambiguous create intents are
stored in `google-connect-sessions.json` with mode 0600; preserve the volume on
restart. Unknown creation outcomes are held for 40 minutes, covering the maximum
accepted 35-minute link lifetime and bounded pre-dispatch/API time, rather than
automatically replayed. Nango pagination starts at page 0, and incomplete inventories fail
closed rather than being treated as no connection.

## Calendar

Tools list calendars, read/search events, read an event, and query free/busy.
Calendar/event mutation and invitations are absent. The sole POST upstream is
`/calendar/v3/freeBusy`, a read operation. Time windows, result counts, response
bytes, and descriptions are bounded, with honest page/truncation indicators.
Google ACLs remain authoritative for each user's accessible calendars.

## Tests

From this checkout:

```bash
npm run check
STRATA_MODULE="file://$PWD/vendor/strata-ebo-turnstile/src/index.js" npm test
npm audit --audit-level=high
```

The vendored module is the same source used by Docker; the historical default
development import instead expects a sibling Strata repository. Deploy only
after live dependency preflight, full-volume snapshots, and exact-image checks.
Use tenant-specific Fly configurations and keys; the included configs are the
amotivv pilot, not generic cross-tenant defaults.

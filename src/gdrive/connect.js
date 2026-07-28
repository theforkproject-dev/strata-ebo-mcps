/**
 * Per-user Google Drive connect endpoints (Lane 2 — mirrors gmail/connect.js).
 *
 *   GET /connectors/nango/gdrive/start?end_user_id=...&email=&display_name=
 *     → 302 into Nango's hosted connect (Google consent) for THIS end user.
 *   GET /connectors/nango/gdrive/status?end_user_id=...
 *     → { status: "ready" | "connection_required", connect_url }
 *
 * The end_user_id is the Agent Anything subject (`aa:<org>:<userId>`) — the
 * same string that arrives as OAuth client_name on minted credentials, which
 * is what lets the MCP side resolve calls back to this connection.
 */
import { createGdriveConnectSession, gdriveConfigured, getGdriveConnectionState } from "./client.js";

export class GdriveConnect {
  constructor(config) {
    this.config = config;
  }

  canHandle(request) {
    if (request.method !== "GET") return false;
    const pathname = new URL(request.url, "http://localhost").pathname;
    return pathname === "/connectors/nango/gdrive/start" || pathname === "/connectors/nango/gdrive/status";
  }

  async handle(request, response) {
    const url = new URL(request.url, "http://localhost");
    const endUserId = String(url.searchParams.get("end_user_id") || "").trim();
    if (!endUserId) return json(response, 400, { error: "end_user_id is required" });
    if (!gdriveConfigured(this.config)) return json(response, 503, { error: "Drive gateway is not configured (Nango secret missing)" });

    if (url.pathname === "/connectors/nango/gdrive/start") {
      try {
        const state = await getGdriveConnectionState(this.config, endUserId);
        const session = await createGdriveConnectSession(this.config, {
          endUserId,
          email: url.searchParams.get("email") || "",
          displayName: url.searchParams.get("display_name") || "",
          connectionId: state.existingConnectionId
        });
        if (!session.connectLink) return json(response, 502, { error: "Nango returned no connect link" });
        response.writeHead(302, { location: session.connectLink, "cache-control": "no-store" });
        response.end();
        return;
      } catch (error) {
        return json(response, 502, { error: error.message });
      }
    }

    const state = await getGdriveConnectionState(this.config, endUserId).catch(() => ({ status: "connection_required" }));
    return json(response, 200, {
      status: state.status,
      integration: this.config.gdrive.providerConfigKey,
      end_user_id: endUserId,
      connect_url: `${this.config.publicBaseUrl}/connectors/nango/gdrive/start?end_user_id=${encodeURIComponent(endUserId)}`
    });
  }
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  response.end(JSON.stringify(body));
}

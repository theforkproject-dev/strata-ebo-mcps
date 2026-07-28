/**
 * Gmail connect flow — the user-authorization half of Lane 2. Agent Anything
 * links here so a user can grant THEIR mailbox: /start 302s into Nango's
 * hosted connect flow (end_user tagged with the caller's subject), /status
 * reports whether a connection exists for that subject. The Nango secret never
 * leaves this gateway; the consent screen shows the workspace's own Google app.
 */
import { createGmailConnectSession, getGmailConnectionState } from "./client.js";

export class GmailConnect {
  constructor(config) {
    this.config = config;
  }

  canHandle(request) {
    const path = new URL(request.url, this.config.publicBaseUrl).pathname;
    return path === "/connectors/nango/gmail/start" || path === "/connectors/nango/gmail/status";
  }

  async handle(request, response) {
    const url = new URL(request.url, this.config.publicBaseUrl);
    if (request.method === "GET" && url.pathname === "/connectors/nango/gmail/start") {
      return this.start(url, response);
    }
    if (request.method === "GET" && url.pathname === "/connectors/nango/gmail/status") {
      return this.status(url, response);
    }
    return json(response, 405, { error: "method not allowed" });
  }

  async start(url, response) {
    const endUserId = url.searchParams.get("end_user_id");
    if (!endUserId) return json(response, 400, { error: "end_user_id is required" });
    try {
      const state = await getGmailConnectionState(this.config, endUserId);
      const session = await createGmailConnectSession(this.config, {
        endUserId,
        email: url.searchParams.get("email") || "",
        displayName: url.searchParams.get("display_name") || "",
        connectionId: state.existingConnectionId
      });
      if (!session.connectLink) return json(response, 502, { error: "Nango did not return a connect link" });
      response.writeHead(302, { location: session.connectLink, "cache-control": "no-store" });
      response.end();
    } catch (error) {
      return json(response, 502, { error: error.message });
    }
  }

  async status(url, response) {
    const endUserId = url.searchParams.get("end_user_id");
    if (!endUserId) return json(response, 400, { error: "end_user_id is required" });
    let state;
    try {
      state = await getGmailConnectionState(this.config, endUserId);
    } catch (error) {
      return json(response, 502, { error: error.message });
    }
    return json(response, 200, {
      status: state.status,
      integration: this.config.gmail.providerConfigKey,
      end_user_id: endUserId,
      connect_url: `${this.config.publicBaseUrl}/connectors/nango/gmail/start?${new URLSearchParams({ end_user_id: endUserId })}`
    });
  }
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

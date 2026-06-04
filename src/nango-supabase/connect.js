import { createNangoSupabaseConnectSession, listNangoSupabaseConnections, nangoSupabaseTags } from "./client.js";

export class NangoSupabaseConnect {
  constructor(config) {
    this.config = config;
  }

  canHandle(request) {
    const path = new URL(request.url, this.config.publicBaseUrl).pathname;
    return path === "/connectors/nango/supabase/start"
      || path === "/connectors/nango/supabase/status";
  }

  async handle(request, response) {
    const url = new URL(request.url, this.config.publicBaseUrl);
    if (request.method === "GET" && url.pathname === "/connectors/nango/supabase/start") {
      return this.start(url, response);
    }
    if (request.method === "GET" && url.pathname === "/connectors/nango/supabase/status") {
      return this.status(url, response);
    }
    return json(response, 405, { error: "method not allowed" });
  }

  async start(url, response) {
    const tags = tagsFromUrl(this.config, url);
    const session = await createNangoSupabaseConnectSession(this.config, { tags });
    if (!session.connect_link) {
      return json(response, 502, { error: "Nango did not return a connect link" });
    }
    response.writeHead(302, { location: session.connect_link, "cache-control": "no-store" });
    response.end();
  }

  async status(url, response) {
    const tags = tagsFromUrl(this.config, url);
    const connections = await listNangoSupabaseConnections(this.config, tags);
    return json(response, 200, {
      status: connections.length > 0 ? "ready" : "connection_required",
      provider_config_key: this.config.nangoSupabase.providerConfigKey,
      connection_count: connections.length,
      tags,
      connect_url: `${this.config.publicBaseUrl}/connectors/nango/supabase/start?${new URLSearchParams(tags)}`
    });
  }
}

function tagsFromUrl(config, url) {
  const defaults = nangoSupabaseTags(config);
  const tags = { ...defaults };
  for (const key of ["end_user_id", "end_user_email", "organization_id", "attexa_poc", "gateway_kind"]) {
    const value = url.searchParams.get(key);
    if (value) tags[key] = value;
  }
  return tags;
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

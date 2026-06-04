import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { connectorManifest, upstreamMcpUrl } from "../src/supabase/canonical.js";
import { nangoMcpJsonRpc, resolveNangoSupabaseConnection } from "../src/nango-supabase/client.js";
import { SupabaseMcpServer } from "../src/supabase-mcp-server.js";

test("nango-supabase mode keeps separate gateway defaults", () => {
  const config = testConfig();

  assert.equal(config.gatewayKind, "nango-supabase");
  assert.equal(config.dataDir, "artifacts/nango-supabase-mcp");
  assert.equal(config.gateway.id, "gateway:nango-supabase-mcp");
  assert.equal(config.gateway.keyId, "gateway:nango-supabase-mcp");
  assert.equal(config.witness.signedRequests.workflowId, "supabase.query");
});

test("nango-supabase connector manifest identifies Nango substrate", () => {
  const config = testConfig();
  const manifest = connectorManifest(config);

  assert.equal(manifest.connector_type, "nango_supabase_mcp");
  assert.equal(manifest.substrate.provider, "nango");
  assert.equal(manifest.substrate.provider_config_key, "supabase-mcp-oauth");
  assert.equal(manifest.upstream.origin, "https://api.nango.dev");
  assert.equal(manifest.upstream.base_url, "https://api.nango.dev/proxy/mcp");
  assert.equal(upstreamMcpUrl(config), "https://api.nango.dev/proxy/mcp");
  assert.deepEqual(manifest.tools.map((tool) => tool.strata_tool), [
    "nango_supabase_list_tables_verified",
    "nango_supabase_inspect_schema_verified",
    "nango_supabase_query_readonly_verified",
    "nango_supabase_search_docs"
  ]);
});

test("nango-supabase connection can be resolved by tags", async () => {
  const config = testConfig();
  const binding = await resolveNangoSupabaseConnection(config, {}, {
    fetchImpl: fakeNangoFetch({ connectionId: "conn_123", projectRef: "ghmfczkhbwfftvpsrghy" })
  });

  assert.equal(binding.ok, true);
  assert.equal(binding.connection_id, "conn_123");
  assert.equal(binding.project_ref, "ghmfczkhbwfftvpsrghy");
  assert.match(binding.credential_fingerprint, /^sha256:/);
});

test("nango mcp json-rpc uses proxy mcp endpoint with project ref", async () => {
  const config = testConfig();
  const seen = [];
  const result = await nangoMcpJsonRpc(config, "conn_123", {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
    params: {}
  }, {
    projectRef: "ghmfczkhbwfftvpsrghy",
    mcpSessionId: "session_abc",
    fetchImpl: async (url, options) => {
      seen.push({ url, options });
      return jsonResponse(200, { jsonrpc: "2.0", id: 1, result: { tools: [] } });
    }
  });

  assert.deepEqual(result, { tools: [] });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, "https://api.nango.dev/proxy/mcp?project_ref=ghmfczkhbwfftvpsrghy");
  assert.equal(seen[0].options.headers["provider-config-key"], "supabase-mcp-oauth");
  assert.equal(seen[0].options.headers["connection-id"], "conn_123");
  assert.equal(seen[0].options.headers["nango-proxy-mcp-session-id"], "session_abc");
  assert.equal(seen[0].options.headers.authorization, "Bearer nango_test_secret");
});

test("nango-supabase docs search accepts plain query strings", async () => {
  const config = testConfig();
  const server = new SupabaseMcpServer(config);
  const registry = await server.dispatch({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
  const searchTool = registry.tools.find((tool) => tool.name === "nango_supabase_search_docs");

  assert.ok(searchTool);
  assert.equal(searchTool.inputSchema.properties.include_content.type, "boolean");
  assert.match(searchTool.description, /plain natural-language search string/i);
});

function testConfig() {
  return loadConfig({
    STRATA_GATEWAY_KIND: "nango-supabase",
    NANGO_SECRET_KEY: "nango_test_secret",
    NANGO_SUPABASE_PROVIDER_CONFIG_KEY: "supabase-mcp-oauth",
    NANGO_SUPABASE_PROJECT_REF: "ghmfczkhbwfftvpsrghy",
    NANGO_SUPABASE_END_USER_ID: "attexa-demo-jason",
    NANGO_SUPABASE_END_USER_EMAIL: "jason@amotivv.com",
    NANGO_SUPABASE_ORGANIZATION_ID: "amotivv-dev",
    PUBLIC_BASE_URL: "https://nango-supabase.example.test",
    CERTIFICATE_BASE_URL: "https://nango-supabase.example.test/certificates",
    WITNESS_URLS: "w1=https://w1.example.test,w2=https://w2.example.test",
    POLICY_WITNESS_URLS: "p1=https://p1.example.test,p2=https://p2.example.test"
  });
}

function fakeNangoFetch({ connectionId, projectRef }) {
  return async (url) => {
    const parsed = new URL(url);
    if (parsed.pathname === "/connections") {
      return jsonResponse(200, { connections: [{ connection_id: connectionId, connection_config: { projectRef } }] });
    }
    throw new Error(`unexpected URL: ${url}`);
  };
}

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Map([["content-type", "application/json"]]),
    async text() {
      return JSON.stringify(body);
    }
  };
}

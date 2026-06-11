import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ResearchMcpServer } from "../src/research-mcp-server.js";
import { callResearchTool, createUsageMeter, researchToolDefinitions } from "../src/research/tools.js";

function testConfig(overrides = {}) {
  return {
    dataDir: mkdtempSync(join(tmpdir(), "research-gateway-test-")),
    research: {
      firecrawlApiKey: "fc-test",
      firecrawlBaseUrl: "https://firecrawl.test",
      perplexityApiKey: "pplx-test",
      perplexityBaseUrl: "https://perplexity.test",
      perplexityAskModel: "sonar-pro",
      openrouterApiKey: "or-test",
      openrouterBaseUrl: "https://openrouter.test/api/v1",
      xsearchModel: "x-ai/grok-4.3",
      assurance: "observed-l1",
      ...overrides
    }
  };
}

function fetchReturning(body, { status = 200 } = {}) {
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body)
  });
}

test("tool definitions: six tools, schemas well-formed, honest x_search description", () => {
  const defs = researchToolDefinitions(testConfig());
  assert.equal(defs.length, 6);
  const names = defs.map((tool) => tool.name);
  assert.deepEqual(names, [
    "firecrawl_search",
    "firecrawl_scrape",
    "perplexity_ask",
    "perplexity_search",
    "x_search",
    "research_gateway_status"
  ]);
  for (const tool of defs) {
    assert.equal(tool.inputSchema.type, "object");
    assert.ok(tool.description.length > 20);
  }
  const xSearch = defs.find((tool) => tool.name === "x_search");
  assert.match(xSearch.description, /Not native X API access/);
  assert.match(xSearch.description, /x-ai\/grok-4\.3/);
});

test("initialize reports protocol, assurance, and instructions", async () => {
  const server = new ResearchMcpServer(testConfig());
  const result = await server.dispatch(
    { method: "initialize", params: { protocolVersion: "2025-11-25" } },
    { session: { sid: "sess-1" } }
  );
  assert.equal(result.protocolVersion, "2025-11-25");
  assert.equal(result.serverInfo.name, "strata-research-mcp-gateway");
  assert.equal(result._meta.assurance, "observed-l1");
  assert.match(result.instructions, /metered/);
});

test("unknown method and unknown tool are rejected cleanly", async () => {
  const server = new ResearchMcpServer(testConfig());
  await assert.rejects(() => server.dispatch({ method: "prompts/list" }), /Method not found/);
  const result = await server.dispatch({ method: "tools/call", params: { name: "email_send", arguments: {} } });
  assert.equal(result.isError, true);
  assert.match(result.structuredContent.error, /Unknown tool/);
});

test("missing vendor key returns configuration error, not a crash", async () => {
  const config = testConfig({ firecrawlApiKey: "" });
  const result = await callResearchTool({ name: "firecrawl_search", args: { query: "test" }, config });
  assert.equal(result.ok, false);
  assert.match(result.error, /FIRECRAWL_API_KEY not configured/);
});

test("firecrawl_search maps results and clamps limit", async () => {
  const config = testConfig();
  let sentBody;
  const fetchImpl = async (url, init) => {
    sentBody = JSON.parse(init.body);
    return fetchReturning({ success: true, data: [{ title: "T", url: "https://example.com", description: "D" }] })();
  };
  const result = await callResearchTool({ name: "firecrawl_search", args: { query: "agent governance", limit: 99 }, config, fetchImpl });
  assert.equal(result.ok, true);
  assert.equal(sentBody.limit, 10); // clamped to ceiling
  assert.equal(result.results[0].url, "https://example.com");
});

test("firecrawl_scrape truncates long markdown", async () => {
  const config = testConfig();
  const longMarkdown = "x".repeat(50_000);
  const fetchImpl = fetchReturning({ success: true, data: { markdown: longMarkdown, metadata: { title: "Big page" } } });
  const result = await callResearchTool({ name: "firecrawl_scrape", args: { url: "https://example.com/big" }, config, fetchImpl });
  assert.equal(result.ok, true);
  assert.equal(result.truncated, true);
  assert.ok(result.markdown.length < 41_000);
  assert.match(result.markdown, /truncated at/);
});

test("firecrawl_scrape rejects non-http urls", async () => {
  const result = await callResearchTool({
    name: "firecrawl_scrape",
    args: { url: "file:///etc/passwd" },
    config: testConfig()
  });
  assert.equal(result.ok, false);
  assert.match(result.error, /http\(s\)/);
});

test("perplexity_ask passes filters and returns citations", async () => {
  const config = testConfig();
  let sentBody;
  const fetchImpl = async (url, init) => {
    sentBody = JSON.parse(init.body);
    return fetchReturning({
      choices: [{ message: { content: "Answer." } }],
      citations: ["https://source.example"],
      usage: { total_tokens: 100 }
    })();
  };
  const result = await callResearchTool({
    name: "perplexity_ask",
    args: { query: "What changed?", recency: "week", domains: ["example.com"] },
    config,
    fetchImpl
  });
  assert.equal(result.ok, true);
  assert.equal(sentBody.search_recency_filter, "week");
  assert.deepEqual(sentBody.search_domain_filter, ["example.com"]);
  assert.deepEqual(result.citations, ["https://source.example"]);
});

test("x_search: happy path extracts citations from annotations", async () => {
  const config = testConfig();
  let sentBody;
  let sentHeaders;
  const fetchImpl = async (url, init) => {
    sentBody = JSON.parse(init.body);
    sentHeaders = init.headers;
    return fetchReturning({
      choices: [
        {
          finish_reason: "stop",
          message: {
            content: "@someone said a thing.",
            annotations: [
              { url_citation: { url: "https://x.com/someone/status/1" } },
              { other: true },
              { url_citation: { url: "https://x.com/other/status/2" } }
            ]
          }
        }
      ],
      usage: { prompt_tokens: 10, completion_tokens: 50 }
    })();
  };
  const result = await callResearchTool({
    name: "x_search",
    args: { query: "what is being said", search_context_size: "high" },
    config,
    fetchImpl
  });
  assert.equal(result.ok, true);
  assert.equal(result.model, "x-ai/grok-4.3");
  assert.deepEqual(result.citations, ["https://x.com/someone/status/1", "https://x.com/other/status/2"]);
  assert.equal(sentBody.plugins[0].id, "web");
  assert.equal(sentBody.plugins[0].search_context_size, "high");
  assert.equal(sentBody.max_tokens, 4096);
  assert.match(sentHeaders["x-title"], /Research Gateway/);
});

test("x_search: 200 OK with finish_reason error is surfaced (known gotcha)", async () => {
  const config = testConfig();
  const fetchImpl = fetchReturning({
    choices: [{ finish_reason: "error", error: { message: "upstream grounding failed" } }]
  });
  const result = await callResearchTool({ name: "x_search", args: { query: "anything" }, config, fetchImpl });
  assert.equal(result.ok, false);
  assert.match(result.error, /Grok error: upstream grounding failed/);
});

test("vendor http errors carry vendor name and message", async () => {
  const config = testConfig();
  const fetchImpl = fetchReturning({ error: { message: "rate limited" } }, { status: 429 });
  const result = await callResearchTool({ name: "perplexity_ask", args: { query: "q" }, config, fetchImpl });
  assert.equal(result.ok, false);
  assert.match(result.error, /Perplexity error: rate limited/);
});

test("research_gateway_status reports vendor configuration honestly", async () => {
  const config = testConfig({ perplexityApiKey: "" });
  const result = await callResearchTool({ name: "research_gateway_status", args: {}, config });
  assert.equal(result.ok, true);
  assert.equal(result.status, "partially_configured");
  assert.equal(result.vendors.firecrawl, true);
  assert.equal(result.vendors.perplexity, false);
  assert.equal(result.assurance, "observed-l1");
});

test("usage meter appends jsonl and aggregates per client", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "research-meter-test-"));
  const meter = createUsageMeter(dataDir);
  meter.record({ clientId: "org-blockwyre", tool: "x_search", ok: true, durationMs: 1200, vendorUsage: { total_tokens: 60 } });
  meter.record({ clientId: "org-blockwyre", tool: "x_search", ok: false, durationMs: 300 });
  meter.record({ clientId: "org-ionia", tool: "perplexity_ask", ok: true, durationMs: 800 });

  const lines = readFileSync(meter.filePath, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(lines.length, 3);
  assert.equal(lines[0].client_id, "org-blockwyre");
  assert.equal(lines[0].vendor_usage.total_tokens, 60);

  const summary = meter.summarize();
  assert.deepEqual(summary["org-blockwyre"].x_search, { calls: 2, errors: 1 });
  assert.deepEqual(summary["org-ionia"].perplexity_ask, { calls: 1, errors: 0 });
  rmSync(dataDir, { recursive: true, force: true });
});

test("tools/call meters with the session client id", async () => {
  const config = testConfig();
  const server = new ResearchMcpServer(config);
  await server.dispatch(
    { method: "tools/call", params: { name: "research_gateway_status", arguments: {} } },
    { session: { oauthClientId: "client-abc" } }
  );
  const summary = server.usageSummary();
  assert.deepEqual(summary["client-abc"].research_gateway_status, { calls: 1, errors: 0 });
  rmSync(config.dataDir, { recursive: true, force: true });
});

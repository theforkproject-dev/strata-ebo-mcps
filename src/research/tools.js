import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

/**
 * Research gateway tool registry: read-only research reach for managed agents.
 * Sensitivity class: read-only — bundled per the locked connector pattern
 * (one gateway per sensitivity class). Vendor keys live gateway-side; callers
 * authenticate via the gateway's OAuth layer and are metered per client.
 *
 * Tools: firecrawl_search, firecrawl_scrape, perplexity_ask,
 * perplexity_search, x_search, research_gateway_status.
 */

const VENDOR_TIMEOUT_MS = 45_000;
const SCRAPE_MAX_CHARS = 40_000;

const XSEARCH_SYSTEM_PROMPT = [
  "You are an X/Twitter search assistant.",
  "Summarize findings factually and concisely.",
  "Include the full text of key posts when available and attribute every claim or quote to its @handle.",
  "If you find nothing relevant, say so clearly — never fabricate posts or handles."
].join(" ");

export function researchToolDefinitions(config) {
  return [
    {
      name: "firecrawl_search",
      description: "Web search via Firecrawl. Returns ranked results with title, URL, and description. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search query" },
          limit: { type: "number", description: "Max results (1-10, default 5)" }
        },
        required: ["query"]
      }
    },
    {
      name: "firecrawl_scrape",
      description: `Scrape a single URL via Firecrawl and return its content as markdown (truncated at ${SCRAPE_MAX_CHARS.toLocaleString()} characters). Read-only.`,
      inputSchema: {
        type: "object",
        properties: {
          url: { type: "string", description: "The URL to scrape" },
          only_main_content: { type: "boolean", description: "Strip navigation/boilerplate (default true)" }
        },
        required: ["url"]
      }
    },
    {
      name: "perplexity_ask",
      description: "Ask a question and get a web-grounded synthesized answer with citation URLs (Perplexity Sonar Pro). Best for factual questions and summaries. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "The question to answer" },
          recency: { type: "string", enum: ["hour", "day", "week", "month", "year"], description: "Restrict search to recent results" },
          domains: { type: "array", items: { type: "string" }, description: "Restrict to these domains (prefix with '-' to exclude)" }
        },
        required: ["query"]
      }
    },
    {
      name: "perplexity_search",
      description: "Web search via Perplexity returning ranked results (title, URL, snippet) without AI synthesis. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search query" },
          max_results: { type: "number", description: "Max results (1-20, default 10)" }
        },
        required: ["query"]
      }
    },
    {
      name: "x_search",
      description: `X (Twitter)-focused answers synthesized by ${config.research.xsearchModel} over OpenRouter web grounding, with citation URLs. Not native X API access — coverage depends on what web grounding surfaces. Read-only.`,
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "What to search X for" },
          max_results: { type: "number", description: "Max grounding results (1-10, default 5)" },
          search_context_size: { type: "string", enum: ["low", "medium", "high"], description: "Grounding depth (default medium)" }
        },
        required: ["query"]
      }
    },
    {
      name: "research_gateway_status",
      description: "Report which research vendors are configured on this gateway and the active x_search model. Call this first if other tools return configuration errors.",
      inputSchema: { type: "object", properties: {} }
    }
  ];
}

export async function callResearchTool({ name, args = {}, config, fetchImpl = fetch }) {
  switch (name) {
    case "firecrawl_search":
      return firecrawlSearch(args, config, fetchImpl);
    case "firecrawl_scrape":
      return firecrawlScrape(args, config, fetchImpl);
    case "perplexity_ask":
      return perplexityAsk(args, config, fetchImpl);
    case "perplexity_search":
      return perplexitySearch(args, config, fetchImpl);
    case "x_search":
      return xSearch(args, config, fetchImpl);
    case "research_gateway_status":
      return gatewayStatus(config);
    default:
      return { ok: false, error: `Unknown tool: ${name}` };
  }
}

export function isResearchToolName(name) {
  return [
    "firecrawl_search",
    "firecrawl_scrape",
    "perplexity_ask",
    "perplexity_search",
    "x_search",
    "research_gateway_status"
  ].includes(name);
}

/* ---------------- vendors ---------------- */

function gatewayStatus(config) {
  const research = config.research;
  return {
    ok: true,
    status: research.firecrawlApiKey && research.perplexityApiKey && research.openrouterApiKey ? "ready" : "partially_configured",
    vendors: {
      firecrawl: Boolean(research.firecrawlApiKey),
      perplexity: Boolean(research.perplexityApiKey),
      openrouter: Boolean(research.openrouterApiKey)
    },
    xsearch_model: research.xsearchModel,
    assurance: research.assurance
  };
}

async function firecrawlSearch(args, config, fetchImpl) {
  const key = config.research.firecrawlApiKey;
  if (!key) return { ok: false, error: "FIRECRAWL_API_KEY not configured on gateway" };
  const query = String(args.query || "").trim();
  if (!query) return { ok: false, error: "query is required" };
  const limit = clamp(args.limit, 1, 10, 5);

  const { ok, status, data } = await vendorJson(fetchImpl, `${config.research.firecrawlBaseUrl}/v1/search`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify({ query, limit })
  });
  if (!ok) return { ok: false, error: vendorError("Firecrawl", status, data) };
  const results = (data?.data || []).map((item) => ({
    title: item.title || "",
    url: item.url || "",
    description: item.description || ""
  }));
  return { ok: true, query, results, result_count: results.length };
}

async function firecrawlScrape(args, config, fetchImpl) {
  const key = config.research.firecrawlApiKey;
  if (!key) return { ok: false, error: "FIRECRAWL_API_KEY not configured on gateway" };
  const url = String(args.url || "").trim();
  if (!/^https?:\/\//i.test(url)) return { ok: false, error: "url must be an http(s) URL" };

  const { ok, status, data } = await vendorJson(fetchImpl, `${config.research.firecrawlBaseUrl}/v1/scrape`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify({
      url,
      formats: ["markdown"],
      onlyMainContent: args.only_main_content !== false
    })
  });
  if (!ok) return { ok: false, error: vendorError("Firecrawl", status, data) };
  let markdown = data?.data?.markdown || "";
  let truncated = false;
  if (markdown.length > SCRAPE_MAX_CHARS) {
    markdown = `${markdown.slice(0, SCRAPE_MAX_CHARS)}\n\n[truncated at ${SCRAPE_MAX_CHARS.toLocaleString()} characters]`;
    truncated = true;
  }
  return {
    ok: true,
    url,
    title: data?.data?.metadata?.title || "",
    markdown,
    truncated
  };
}

async function perplexityAsk(args, config, fetchImpl) {
  const key = config.research.perplexityApiKey;
  if (!key) return { ok: false, error: "PERPLEXITY_API_KEY not configured on gateway" };
  const query = String(args.query || "").trim();
  if (!query) return { ok: false, error: "query is required" };

  const body = {
    model: config.research.perplexityAskModel,
    messages: [{ role: "user", content: query }],
    ...(args.recency ? { search_recency_filter: args.recency } : {}),
    ...(Array.isArray(args.domains) && args.domains.length ? { search_domain_filter: args.domains.slice(0, 10) } : {})
  };
  const { ok, status, data } = await vendorJson(fetchImpl, `${config.research.perplexityBaseUrl}/chat/completions`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!ok) return { ok: false, error: vendorError("Perplexity", status, data) };
  return {
    ok: true,
    answer: data?.choices?.[0]?.message?.content || "",
    citations: Array.isArray(data?.citations) ? data.citations : [],
    model: body.model,
    usage: data?.usage || {}
  };
}

async function perplexitySearch(args, config, fetchImpl) {
  const key = config.research.perplexityApiKey;
  if (!key) return { ok: false, error: "PERPLEXITY_API_KEY not configured on gateway" };
  const query = String(args.query || "").trim();
  if (!query) return { ok: false, error: "query is required" };
  const maxResults = clamp(args.max_results, 1, 20, 10);

  const { ok, status, data } = await vendorJson(fetchImpl, `${config.research.perplexityBaseUrl}/search`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify({ query, max_results: maxResults })
  });
  if (!ok) return { ok: false, error: vendorError("Perplexity", status, data) };
  const results = (data?.results || []).map((item) => ({
    title: item.title || "",
    url: item.url || "",
    snippet: item.snippet || item.description || "",
    date: item.date || item.published_date || null
  }));
  return { ok: true, query, results, result_count: results.length };
}

async function xSearch(args, config, fetchImpl) {
  const key = config.research.openrouterApiKey;
  if (!key) return { ok: false, error: "OPENROUTER_API_KEY not configured on gateway" };
  const query = String(args.query || "").trim();
  if (!query) return { ok: false, error: "query is required" };
  const maxResults = clamp(args.max_results, 1, 10, 5);
  const contextSize = ["low", "medium", "high"].includes(args.search_context_size) ? args.search_context_size : "medium";
  const model = config.research.xsearchModel;

  const { ok, status, data } = await vendorJson(fetchImpl, `${config.research.openrouterBaseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${key}`,
      "content-type": "application/json",
      "http-referer": "https://attexa.ai",
      "x-title": "Attexa Research Gateway"
    },
    body: JSON.stringify({
      model,
      max_tokens: 4096,
      plugins: [{ id: "web", max_results: maxResults, search_context_size: contextSize }],
      messages: [
        { role: "system", content: XSEARCH_SYSTEM_PROMPT },
        { role: "user", content: query }
      ]
    })
  });
  if (!ok) return { ok: false, error: vendorError("OpenRouter", status, data) };

  // Known gotcha: OpenRouter can return 200 OK with finish_reason "error".
  const choice = data?.choices?.[0];
  if (choice?.finish_reason === "error") {
    const message = choice?.error?.message || data?.error?.message || "model returned an error finish_reason";
    return { ok: false, error: `Grok error: ${message}` };
  }

  const citations = (choice?.message?.annotations || [])
    .filter((annotation) => annotation?.url_citation?.url)
    .map((annotation) => annotation.url_citation.url);

  return {
    ok: true,
    answer: choice?.message?.content || "",
    citations,
    model,
    usage: data?.usage || {}
  };
}

/* ---------------- usage metering ---------------- */

export function createUsageMeter(dataDir) {
  const filePath = join(dataDir, "research-usage.jsonl");
  let dirReady = false;
  const totals = new Map(); // `${clientId}\u0000${tool}` -> { calls, errors }

  return {
    record({ clientId = "unknown", tool, ok, durationMs = 0, vendorUsage = null }) {
      const entry = {
        ts: new Date().toISOString(),
        client_id: clientId,
        tool,
        ok: Boolean(ok),
        duration_ms: Math.round(durationMs),
        ...(vendorUsage ? { vendor_usage: vendorUsage } : {})
      };
      try {
        if (!dirReady) {
          mkdirSync(dataDir, { recursive: true });
          dirReady = true;
        }
        appendFileSync(filePath, `${JSON.stringify(entry)}\n`, "utf8");
      } catch {
        /* metering must never break a tool call */
      }
      const totalsKey = `${entry.client_id}\u0000${tool}`;
      const current = totals.get(totalsKey) || { calls: 0, errors: 0 };
      current.calls += 1;
      if (!entry.ok) current.errors += 1;
      totals.set(totalsKey, current);
      return entry;
    },
    summarize() {
      const byClient = {};
      for (const [totalsKey, value] of totals) {
        const [clientId, tool] = totalsKey.split("\u0000");
        byClient[clientId] = byClient[clientId] || {};
        byClient[clientId][tool] = { ...value };
      }
      return byClient;
    },
    filePath
  };
}

/* ---------------- helpers ---------------- */

function clamp(value, min, max, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.round(parsed)));
}

async function vendorJson(fetchImpl, url, init) {
  let response;
  try {
    response = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(VENDOR_TIMEOUT_MS) });
  } catch (error) {
    return { ok: false, status: 0, data: { error: { message: error.message } } };
  }
  let data = null;
  const text = await response.text();
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text?.slice(0, 500) };
  }
  return { ok: response.ok, status: response.status, data };
}

function vendorError(vendor, status, data) {
  const message = data?.error?.message || data?.error || data?.message || data?.raw || (status ? `HTTP ${status}` : "request failed");
  return `${vendor} error: ${typeof message === "string" ? message : JSON.stringify(message)}`;
}

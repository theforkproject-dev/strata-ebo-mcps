#!/usr/bin/env node
import { createServer } from "node:http";
import { normalizeBundleUrl, verifyCertificateBundleUrl } from "../src/verify/certificate-verifier.js";

const host = process.env.HOST || "0.0.0.0";
const port = Number(process.env.PORT || 8080);

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || `${host}:${port}`}`);
    if (request.method === "GET" && url.pathname === "/health") {
      return json(response, 200, { ok: true, name: "strata-certificate-verifier" });
    }
    if (request.method === "GET" && url.pathname === "/") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end(indexHtml());
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/verify") {
      const body = await readJson(request);
      if (!body.bundle_url || typeof body.bundle_url !== "string") {
        return json(response, 400, { ok: false, error: "bundle_url is required" });
      }
      const normalizedUrl = normalizeBundleUrl(body.bundle_url);
      const report = await verifyCertificateBundleUrl(normalizedUrl);
      return json(response, report.ok ? 200 : 422, report);
    }
    return json(response, 404, { ok: false, error: "not found" });
  } catch (error) {
    return json(response, 500, { ok: false, error: error.message, hint: verifierHint(error.message) });
  }
});

server.listen(port, host, () => {
  console.log(JSON.stringify({ ok: true, url: `http://${host}:${port}` }));
});

async function readJson(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

function verifierHint(message) {
  if (/certificate not found|returned 404/i.test(message)) {
    return "The gateway could not find that certificate bundle. Current demo certificates are stored on the Tinfoil gateway ramdisk, so older bundle URLs stop working after a gateway relaunch. Generate a fresh certificate or use a bundle saved as an artifact.";
  }
  if (/Invalid URL/i.test(message)) {
    return "Paste either the certificate URL or the /bundle URL returned by the MCP tool.";
  }
  return "Check that the URL is reachable and points to a Strata certificate bundle.";
}

function indexHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Strata Certificate Verifier</title>
  <style>
    :root { color-scheme: light dark; --ok:#117a37; --bad:#a32020; --warn:#9a6200; --ink:#171717; --muted:#666; --line:#d8d8d8; --bg:#faf9f5; --card:#fff; }
    @media (prefers-color-scheme: dark) { :root { --ink:#f3f1ea; --muted:#b8b3a8; --line:#3b3934; --bg:#151412; --card:#1f1d1a; } }
    body { margin:0; background:var(--bg); color:var(--ink); font:16px/1.5 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    main { max-width:1060px; margin:0 auto; padding:44px 24px 72px; }
    h1 { font-family: Georgia, "Times New Roman", serif; font-size:44px; line-height:1.05; margin:0 0 12px; }
    p.lede { color:var(--muted); font-size:18px; max-width:780px; margin:0 0 28px; }
    form { display:grid; gap:12px; grid-template-columns:1fr auto; margin:28px 0; }
    input { font:inherit; padding:14px 16px; border:1px solid var(--line); border-radius:10px; background:var(--card); color:var(--ink); min-width:0; }
    button { font:700 15px/1 ui-sans-serif, system-ui; padding:0 22px; border:0; border-radius:10px; background:#111; color:#fff; cursor:pointer; }
    button:disabled { opacity:.55; cursor:wait; }
    .card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:22px; margin-top:18px; box-shadow:0 1px 2px rgb(0 0 0 / .04); }
    .verdict { display:flex; align-items:center; justify-content:space-between; gap:20px; }
    .badge { font-weight:800; letter-spacing:.08em; border-radius:999px; padding:8px 12px; font-size:13px; }
    .valid { background:rgb(17 122 55 / .12); color:var(--ok); }
    .invalid { background:rgb(163 32 32 / .12); color:var(--bad); }
    .grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; margin-top:16px; }
    .metric { border:1px solid var(--line); border-radius:12px; padding:12px; }
    .metric b { display:block; font-size:24px; }
    .metric span { color:var(--muted); font-size:13px; }
    .explain { display:grid; gap:14px; }
    .claim { border:1px solid var(--line); border-radius:14px; padding:16px; background:rgb(127 127 127 / .045); }
    .claim h3 { margin:0 0 6px; font-size:17px; }
    .claim p { margin:0; color:var(--muted); }
    .claim.good { border-color:rgb(17 122 55 / .35); }
    .claim.bad { border-color:rgb(163 32 32 / .35); }
    .story { font-size:18px; margin-top:16px; max-width:850px; }
    details { border-top:1px solid var(--line); padding:14px 0; }
    details:first-of-type { border-top:0; }
    summary { cursor:pointer; font-weight:700; }
    code, pre { font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    pre { overflow:auto; padding:14px; border-radius:10px; background:rgb(127 127 127 / .10); }
    .check { display:flex; align-items:flex-start; justify-content:space-between; gap:18px; padding:8px 0; border-top:1px solid var(--line); }
    .check:first-child { border-top:0; }
    .pass { color:var(--ok); } .fail { color:var(--bad); } .warn { color:var(--warn); }
    .small { color:var(--muted); font-size:13px; overflow-wrap:anywhere; }
    @media (max-width:760px) { form { grid-template-columns:1fr; } button { height:48px; } .grid { grid-template-columns:1fr; } h1 { font-size:34px; } }
  </style>
</head>
<body>
  <main>
    <h1>Strata Certificate Verifier</h1>
    <p class="lede">Paste a Strata certificate or bundle URL. This verifier runs outside Claude Desktop and outside the gateway, then checks the certificate, receipt chain, policy quorum, registry authority, and Tinfoil attestations.</p>
    <form id="verify-form">
      <input id="bundle-url" name="bundle_url" placeholder="https://.../certificates/... or https://.../certificates/.../bundle" autocomplete="off" spellcheck="false" required>
      <button id="verify-button" type="submit">Verify Certificate</button>
    </form>
    <section id="result"></section>
  </main>
  <script>
    const form = document.getElementById('verify-form');
    const input = document.getElementById('bundle-url');
    const button = document.getElementById('verify-button');
    const result = document.getElementById('result');
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      button.disabled = true;
      result.innerHTML = '<div class="card">Verifying bundle...</div>';
      try {
        const response = await fetch('/api/verify', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ bundle_url: input.value }) });
        const report = await response.json();
        if (!report.checks && report.error) {
          renderError(report);
          return;
        }
        render(report);
      } catch (error) {
        result.innerHTML = '<div class="card"><span class="badge invalid">ERROR</span><pre>' + escapeHtml(error.message) + '</pre></div>';
      } finally {
        button.disabled = false;
      }
    });
    function render(report) {
      const groups = groupChecks(report.checks || []);
      result.innerHTML = '<div class="card">' +
        '<div class="verdict"><div><h2>' + (report.ok ? 'Certificate Verified' : 'Certificate Invalid') + '</h2><div class="small">' + escapeHtml(report.certificate?.url || report.source_url || '') + '</div></div>' +
        '<span class="badge ' + (report.ok ? 'valid' : 'invalid') + '">' + (report.ok ? 'VALID' : 'INVALID') + '</span></div>' +
        '<div class="grid"><div class="metric"><b>' + (report.summary?.pass ?? 0) + '</b><span>checks passed</span></div><div class="metric"><b>' + (report.summary?.warn ?? 0) + '</b><span>warnings</span></div><div class="metric"><b>' + (report.summary?.fail ?? 0) + '</b><span>failures</span></div></div>' +
        '<p class="story">' + escapeHtml(narrative(report)) + '</p>' +
        '<div class="small" style="margin-top:14px">Certificate digest: <code>' + escapeHtml(report.certificate?.digest || '') + '</code></div></div>' +
        '<div class="card"><h2>What this proves</h2><div class="explain">' + explanationCards(report).map(renderClaim).join('') + '</div></div>' +
        Object.entries(groups).map(([name, checks]) => '<div class="card"><details open><summary>' + escapeHtml(title(name)) + '</summary>' + checks.map(renderCheck).join('') + '</details></div>').join('') +
        '<div class="card"><details><summary>Raw verifier report</summary><pre>' + escapeHtml(JSON.stringify(report, null, 2)) + '</pre></details></div>';
    }
    function renderError(report) {
      result.innerHTML = '<div class="card"><div class="verdict"><div><h2>Could not verify this URL</h2><p class="story">' + escapeHtml(report.hint || 'The verifier could not load or parse the certificate bundle.') + '</p></div><span class="badge invalid">ERROR</span></div><pre>' + escapeHtml(report.error || 'Unknown error') + '</pre></div>';
    }
    function narrative(report) {
      if (!report.ok) return 'The verifier found at least one failed check. This bundle should not be treated as a valid Strata certificate until the failed checks are resolved.';
      const provider = report.certificate?.provider || 'the configured provider';
      const action = report.certificate?.action?.mcp_tool_name || 'the MCP tool';
      return 'This verifier independently checked that an authenticated MCP client invoked ' + action + ', the gateway executed a ' + provider + ' side effect, and the resulting evidence bundle is internally consistent and externally witnessed.';
    }
    function explanationCards(report) {
      const ok = (prefix) => (report.checks || []).filter((check) => check.name.startsWith(prefix)).every((check) => check.severity !== 'fail');
      const has = (name) => (report.checks || []).find((check) => check.name === name && check.ok);
      return [
        { title: 'The certificate was not tampered with', good: has('certificate.digest'), text: 'The verifier recomputed the certificate digest and matched it against the digest carried in the bundle.' },
        { title: 'The action followed the receipt chain', good: ok('receipt_chain'), text: 'The session receipts and checkpoint form a valid signed chain, so the recorded action flow is internally consistent.' },
        { title: 'The policy decision matched signed rules', good: ok('policy_bundle') && ok('registry.l2'), text: 'The policy bundle digest matched the certificate, and the Level 2 policy witnesses authorized the email under that policy.' },
        { title: 'The witness and registry authority checked out', good: ok('registry') && ok('authority_pins'), text: 'The registry epoch, registry trust anchor, and policy digest matched the pinned values, so the registry host was not treated as the source of authority.' },
        { title: 'The gateway runtime was Tinfoil-attested', good: ok('gateway_attestation'), text: 'The gateway attestation bundle was verified with the published Tinfoil verifier, tying the action gateway to a measured enclave runtime.' },
        { title: 'The L1 witness runtime was Tinfoil-attested', good: ok('l1_attestation'), text: 'The Level 1 mechanical witness attestation bundle was verified, tying the witness signature path to a measured enclave runtime.' },
        { title: 'Operator identity was authorized', good: has('operator_identity.version') && ok('operator_identity') && ok('operator_registry'), text: 'The operator admission key was bound to a signed operator registry record that authorized this tenant, workflow, tool, and policy hash.' }
      ];
    }
    function renderClaim(claim) { return '<div class="claim ' + (claim.good ? 'good' : 'bad') + '"><h3>' + (claim.good ? '✓ ' : '× ') + escapeHtml(claim.title) + '</h3><p>' + escapeHtml(claim.text) + '</p></div>'; }
    function groupChecks(checks) { return checks.reduce((acc, check) => { const key = check.name.split('.')[0]; (acc[key] ||= []).push(check); return acc; }, {}); }
    function renderCheck(check) { return '<div class="check"><div><b>' + escapeHtml(check.name) + '</b>' + (check.error ? '<div class="small">' + escapeHtml(check.error) + '</div>' : '') + '</div><strong class="' + check.severity + '">' + check.severity.toUpperCase() + '</strong></div>'; }
    function title(name) { return ({bundle:'Bundle', certificate:'Certificate', receipts:'Receipts', receipt_chain:'Receipt chain', policy_bundle:'Policy bundle', authority_pins:'Authority pins', registry:'Registry authority', operator_registry:'Operator registry', operator_identity:'Operator identity', gateway_attestation:'Gateway Tinfoil attestation', l1_attestation:'L1 Tinfoil attestation'}[name] || name); }
    function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])); }
  </script>
</body>
</html>`;
}

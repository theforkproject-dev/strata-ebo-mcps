#!/usr/bin/env node
import { createServer } from "node:http";
import { normalizeBundleUrl, verifyCertificateBundle, verifyCertificateBundleUrl } from "../src/verify/certificate-verifier.js";

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
    if (request.method === "GET" && url.pathname === "/pilot") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end(pilotHtml());
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/verify") {
      const body = await readJson(request);
      if (body.bundle && typeof body.bundle === "object") {
        const report = await verifyCertificateBundle(body.bundle, { sourceUrl: body.source_url || "inline bundle JSON" });
        return json(response, report.ok ? 200 : 422, report);
      }
      if (body.bundle_json && typeof body.bundle_json === "string") {
        const bundle = JSON.parse(body.bundle_json);
        const report = await verifyCertificateBundle(bundle, { sourceUrl: body.source_url || "inline bundle JSON" });
        return json(response, report.ok ? 200 : 422, report);
      }
      if (!body.bundle_url || typeof body.bundle_url !== "string") {
        return json(response, 400, { ok: false, error: "bundle_url or bundle is required" });
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
    .topnav { display:flex; gap:16px; align-items:center; margin-bottom:28px; font-size:14px; }
    .topnav a { color:var(--muted); text-decoration:none; border-bottom:1px solid transparent; }
    .topnav a:hover { color:var(--ink); border-bottom-color:var(--ink); }
    h1 { font-family: Georgia, "Times New Roman", serif; font-size:44px; line-height:1.05; margin:0 0 12px; }
    h2 { margin:0 0 12px; }
    p.lede { color:var(--muted); font-size:18px; max-width:780px; margin:0 0 28px; }
    .intro p { color:var(--muted); margin:0; max-width:850px; }
    .intro-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin-top:18px; }
    .intro-card { border:1px solid var(--line); border-radius:14px; padding:14px; background:rgb(127 127 127 / .035); }
    .intro-card b { display:block; margin-bottom:6px; }
    .intro-card span { color:var(--muted); font-size:14px; }
    .text-link { color:var(--ink); font-weight:700; text-decoration:none; border-bottom:1px solid var(--ink); }
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
    .facts { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; margin-top:14px; }
    .fact { border:1px solid var(--line); border-radius:12px; padding:12px; background:rgb(127 127 127 / .035); min-width:0; }
    .fact b { display:block; font-size:13px; color:var(--muted); margin-bottom:4px; }
    .fact code { overflow-wrap:anywhere; }
    .witnesses { display:grid; gap:10px; margin-top:14px; }
    .witness { border:1px solid var(--line); border-radius:12px; padding:12px; }
    .witness strong { display:block; margin-bottom:4px; }
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
     @media (max-width:900px) { .intro-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } }
     @media (max-width:760px) { form { grid-template-columns:1fr; } button { height:48px; } .grid, .facts, .intro-grid { grid-template-columns:1fr; } h1 { font-size:34px; } }
  </style>
</head>
<body>
  <main>
    <nav class="topnav"><a href="/">Verifier</a><a href="/pilot">Pilot overview</a></nav>
    <h1>Strata Certificate Verifier</h1>
    <p class="lede">Paste a Strata certificate or bundle URL. This verifier runs outside Claude Desktop and outside the gateway, then checks the certificate, receipt chain, policy quorum, registry authority, and Tinfoil attestations.</p>
    <section class="card intro">
      <h2>Why this matters</h2>
      <p>This certificate proves an AI agent did not merely claim it sent an email. The action path itself was policy-gated before execution, then witnessed, executed by an attested gateway, and packaged into durable evidence that can be checked later.</p>
      <div class="intro-grid">
        <div class="intro-card"><b>Action integrity</b><span>The email action and provider result are bound into a signed receipt chain.</span></div>
        <div class="intro-card"><b>Policy enforcement</b><span>The gateway can only mint the side-effect capability after signed policy-witness approval.</span></div>
        <div class="intro-card"><b>Witnessed execution</b><span>A Tinfoil L1 quorum notarizes the enforced action path before and after the side effect.</span></div>
        <div class="intro-card"><b>Operator legitimacy</b><span>The operator key is checked against a signed registry record and policy scope.</span></div>
        <div class="intro-card"><b>Durable evidence</b><span>The complete bundle is published as a no-overwrite object for later audit.</span></div>
      </div>
      <p style="margin-top:16px"><a class="text-link" href="/pilot">Read the non-technical pilot overview</a></p>
    </section>
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
        renderProofSnapshot(report) +
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
    function renderProofSnapshot(report) {
      const e = report.evidence || {};
      const l1 = e.l1 || {};
      const l2 = e.l2 || {};
      const operator = e.operator || {};
      const registry = e.registry || {};
      const durable = e.durable_publication || {};
      const gateway = e.gateway || {};
      const facts = [
        ['L1 quorum', l1.quorum || 'unknown'],
        ['L1 Tinfoil witnesses', String(l1.witness_count ?? 0) + ' total, ' + String(l1.distinct_config_repos ?? 0) + ' config repos'],
        ['L2 policy quorum', l2.policy_witness_quorum || 'unknown'],
        ['Operator', operator.operator_id || 'unknown'],
        ['Email registry epoch', registry.registry_epoch_id || 'unknown'],
        ['Registry digest', registry.registry_epoch_digest || 'unknown'],
        ['Gateway release', gateway.config_tag || 'unknown'],
        ['Durable publication', durable.backend ? durable.backend + ', ' + (durable.retention_mode || 'no retention metadata') : 'not included']
      ];
      return '<div class="card"><h2>Proof snapshot</h2>' +
        '<div class="facts">' + facts.map(([label, value]) => '<div class="fact"><b>' + escapeHtml(label) + '</b><code>' + escapeHtml(value) + '</code></div>').join('') + '</div>' +
        renderWitnesses(l1.witnesses || []) +
        (durable.bundle_url ? '<div class="small" style="margin-top:14px">Durable bundle URL: <code>' + escapeHtml(durable.bundle_url) + '</code></div>' : '') +
        '</div>';
    }
    function renderWitnesses(witnesses) {
      if (!witnesses.length) return '';
      return '<h3 style="margin:18px 0 8px">L1 witness attestations</h3><div class="witnesses">' + witnesses.map((witness) =>
        '<div class="witness"><strong>' + escapeHtml(witness.witness_id || 'unknown witness') + '</strong>' +
        '<div class="small">Repo: <code>' + escapeHtml(witness.config_repo || '') + '</code></div>' +
        '<div class="small">Tag: <code>' + escapeHtml(witness.config_tag || '') + '</code></div>' +
        '<div class="small">Release digest: <code>' + escapeHtml(witness.release_digest || '') + '</code></div>' +
        '</div>').join('') + '</div>';
    }
    function explanationCards(report) {
      const ok = (prefix) => (report.checks || []).filter((check) => check.name.startsWith(prefix)).every((check) => check.severity !== 'fail');
      const has = (name) => (report.checks || []).find((check) => check.name === name && check.ok);
      const l1Quorum = report.evidence?.l1?.quorum || 'the configured L1 quorum';
      return [
        { title: 'The certificate was not tampered with', good: has('certificate.digest'), text: 'The verifier recomputed the certificate digest and matched it against the digest carried in the bundle.' },
        { title: 'The action followed the receipt chain', good: ok('receipt_chain'), text: 'The session receipts and checkpoint form a valid signed chain, so the recorded action flow is internally consistent.' },
        { title: 'The action was policy-enforced before execution', good: ok('policy_bundle') && ok('registry.l2'), text: 'The policy bundle digest matched the certificate, and Level 2 witnesses authorized this exact email before the gateway minted the side-effect capability.' },
        { title: 'The L1 quorum checked out', good: ok('registry.l1') && ok('l1_attestation'), text: 'The certificate satisfied ' + l1Quorum + ' mechanical witness authorization, and each included Tinfoil witness attestation verified independently.' },
        { title: 'The registry authority checked out', good: ok('registry') && ok('authority_pins'), text: 'The registry epoch, registry trust anchor, and policy digest matched the pinned values, so the registry host was not treated as the source of authority.' },
        { title: 'The gateway runtime was Tinfoil-attested', good: ok('gateway_attestation'), text: 'The gateway attestation bundle was verified with the published Tinfoil verifier, tying the action gateway to a measured enclave runtime.' },
        { title: 'Operator identity was authorized', good: has('operator_identity.version') && ok('operator_identity') && ok('operator_registry'), text: 'The operator admission key was bound to a signed operator registry record that authorized this tenant, workflow, tool, and policy hash.' },
        { title: 'The bundle is durable evidence', good: has('durable_publication.present') && ok('durable_publication'), text: 'The complete certificate bundle was published to the configured durable object store with no-overwrite publication metadata.' }
      ];
    }
    function renderClaim(claim) { return '<div class="claim ' + (claim.good ? 'good' : 'bad') + '"><h3>' + (claim.good ? '✓ ' : '× ') + escapeHtml(claim.title) + '</h3><p>' + escapeHtml(claim.text) + '</p></div>'; }
    function groupChecks(checks) { return checks.reduce((acc, check) => { const key = check.name.split('.')[0]; (acc[key] ||= []).push(check); return acc; }, {}); }
    function renderCheck(check) { return '<div class="check"><div><b>' + escapeHtml(check.name) + '</b>' + (check.error ? '<div class="small">' + escapeHtml(check.error) + '</div>' : '') + '</div><strong class="' + check.severity + '">' + check.severity.toUpperCase() + '</strong></div>'; }
    function title(name) { return ({bundle:'Bundle', certificate:'Certificate', receipts:'Receipts', receipt_chain:'Receipt chain', policy_bundle:'Policy bundle', authority_pins:'Authority pins', durable_publication:'Durable publication', registry:'Registry authority', operator_registry:'Operator registry', operator_identity:'Operator identity', gateway_attestation:'Gateway Tinfoil attestation', l1_attestation:'L1 Tinfoil attestation'}[name] || name); }
    function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])); }
  </script>
</body>
</html>`;
}

function pilotHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Strata Verified Email Pilot Overview</title>
  <style>
    :root { color-scheme: light dark; --ink:#171717; --muted:#666; --line:#d8d8d8; --bg:#faf9f5; --card:#fff; --accent:#117a37; }
    @media (prefers-color-scheme: dark) { :root { --ink:#f3f1ea; --muted:#b8b3a8; --line:#3b3934; --bg:#151412; --card:#1f1d1a; } }
    body { margin:0; background:var(--bg); color:var(--ink); font:16px/1.55 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    main { max-width:980px; margin:0 auto; padding:44px 24px 72px; }
    .topnav { display:flex; gap:16px; align-items:center; margin-bottom:28px; font-size:14px; }
    .topnav a { color:var(--muted); text-decoration:none; border-bottom:1px solid transparent; }
    .topnav a:hover { color:var(--ink); border-bottom-color:var(--ink); }
    h1 { font-family: Georgia, "Times New Roman", serif; font-size:46px; line-height:1.05; margin:0 0 14px; }
    h2 { margin:0 0 12px; }
    p.lede { color:var(--muted); font-size:19px; max-width:820px; margin:0 0 28px; }
    .card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:22px; margin-top:18px; box-shadow:0 1px 2px rgb(0 0 0 / .04); }
    .grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }
    .claim { border:1px solid var(--line); border-radius:14px; padding:16px; background:rgb(127 127 127 / .035); }
    .claim b { display:block; margin-bottom:6px; }
    .claim span, .muted { color:var(--muted); }
    code, pre { font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    pre { overflow:auto; padding:14px; border-radius:10px; background:rgb(127 127 127 / .10); }
    .button-row { display:flex; gap:12px; flex-wrap:wrap; margin-top:18px; }
    .button { display:inline-block; border-radius:10px; padding:12px 16px; background:#111; color:#fff; text-decoration:none; font-weight:800; }
    .button.secondary { background:transparent; color:var(--ink); border:1px solid var(--line); }
    .callout { border-left:4px solid var(--accent); padding-left:16px; color:var(--muted); }
    @media (max-width:760px) { .grid { grid-template-columns:1fr; } h1 { font-size:34px; } }
  </style>
</head>
<body>
  <main>
    <nav class="topnav"><a href="/">Verifier</a><a href="/pilot">Pilot overview</a></nav>
    <h1>Verified Email Pilot Overview</h1>
    <p class="lede">Strata turns an AI side effect into a policy-enforced action path and a replayable evidence bundle. A reviewer can verify both that the action was allowed before execution and what happened afterward.</p>

    <section class="card">
      <h2>The Problem</h2>
      <p>AI agents increasingly take actions in the real world: send emails, approve workflows, update records, or trigger payments. A normal log can say an action happened, but after-the-fact reporting is not enough for governed side effects.</p>
      <p>The stronger requirement is enforcement: the action channel should require policy approval before the provider call, and then produce evidence that the enforced path was followed.</p>
      <p class="callout">The pilot asks a narrower question: can we require policy and witness approval for one real AI-sent email, then produce a durable certificate that lets an outside reviewer verify the full path end to end?</p>
    </section>

    <section class="card">
      <h2>Enforcement, Not Just Logging</h2>
      <p>Strata is not only a black-box recorder for AI actions. The gateway commits to the intended action, obtains signed Level 2 policy-witness approval, and only then mints a single-use capability for the exact side effect. The side-effect adapter requires that capability before it calls the provider.</p>
      <p>The certificate is the proof that this enforced path was followed. If the policy witnesses do not approve, or if the registry does not authorize the witnesses/operator, the certified action should fail before the side-effect path completes.</p>
    </section>

    <section class="card">
      <h2>What The Golden Bundle Demonstrates</h2>
      <div class="grid">
        <div class="claim"><b>Real action</b><span>Claude Desktop invoked a remote MCP tool, and the gateway sent a real email through Resend.</span></div>
        <div class="claim"><b>Policy enforcement</b><span>Level 2 policy witnesses checked the email against the signed policy bundle before the side-effect capability was minted.</span></div>
        <div class="claim"><b>Mechanical quorum</b><span>A 2-of-3 Level 1 Tinfoil witness quorum notarized the action path around the side effect.</span></div>
        <div class="claim"><b>Attested runtimes</b><span>The gateway and all three L1 witnesses include Tinfoil evidence verified with Tinfoil's official verifier.</span></div>
        <div class="claim"><b>Operator legitimacy</b><span>The operator admission key is bound to a signed registry record authorizing this tenant, workflow, tool, and policy hash.</span></div>
        <div class="claim"><b>Durable evidence</b><span>The complete certificate bundle is published to S3/CloudFront as a no-overwrite durable verifier input.</span></div>
      </div>
    </section>

    <section class="card">
      <h2>Canonical Evidence</h2>
      <p class="muted">Use this durable bundle URL in the verifier. It is the canonical pilot artifact.</p>
      <pre>https://d33vpkebicuw51.cloudfront.net/certificates/email/email_1778251243530_a11429ad/68543b96e4e4978d53cc2d38578058331cf9f4a4cfde450b78126376c40d311c/bundle.json</pre>
      <p>Expected result: <code>50 pass</code>, <code>0 warn</code>, <code>0 fail</code>.</p>
      <div class="button-row">
        <a class="button" href="/">Open verifier</a>
        <a class="button secondary" href="https://d33vpkebicuw51.cloudfront.net/certificates/email/email_1778251243530_a11429ad/68543b96e4e4978d53cc2d38578058331cf9f4a4cfde450b78126376c40d311c/bundle.json">Open bundle JSON</a>
      </div>
    </section>

    <section class="card">
      <h2>How To Read The Verifier</h2>
      <div class="grid">
        <div class="claim"><b>Proof snapshot</b><span>The high-level summary: L1 quorum, L2 quorum, operator, registry digest, gateway release, and durable publication.</span></div>
        <div class="claim"><b>What this proves</b><span>Plain-English claims derived from the technical checks, including both pre-execution policy enforcement and after-the-fact evidence.</span></div>
        <div class="claim"><b>Grouped checks</b><span>The raw verification surface. This is where auditors can inspect exact pass/warn/fail details.</span></div>
        <div class="claim"><b>Raw report</b><span>Machine-readable JSON output for downstream audit tooling or independent review.</span></div>
      </div>
    </section>

    <section class="card">
      <h2>Pilot Caveats</h2>
      <p>The pilot demonstrates the full verification mechanics, but it is not the final production assurance posture.</p>
      <p>The three L1 witnesses are independently keyed, separately configured, separately built, and separately Tinfoil-attested, but they are still administered under the same project/operator for pilot purposes.</p>
      <p>L2 policy witnesses and the email registry are still Fly-hosted. They are signed and pinned, so Fly is a delivery layer rather than raw authority, but production P3/P4 deployments should move toward independent L2 operators, durable/static registry publication, and public transparency anchoring.</p>
    </section>
  </main>
</body>
</html>`;
}

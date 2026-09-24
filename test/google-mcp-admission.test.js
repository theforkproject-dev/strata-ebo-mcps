import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

async function unusedPort() {
  const server = createServer(); server.listen(0, "127.0.0.1"); await once(server, "listening");
  const port = server.address().port; await new Promise((resolve) => server.close(resolve)); return port;
}

for (const oauth of [false, true]) {
  test(`Google MCP requires an OAuth caller even when a shared bearer is configured (OAuth ${oauth})`, async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "google-mcp-admission-"));
    const port = await unusedPort(), base = `http://127.0.0.1:${port}`;
    const child = spawn(process.execPath, ["src/server.js"], {
      cwd: new URL("../", import.meta.url), stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, STRATA_MODULE: new URL("../vendor/strata-ebo-turnstile/src/index.js", import.meta.url).href,
        GATEWAY_KIND: "gcalendar", HOST: "127.0.0.1", PORT: String(port), DATA_DIR: dataDir,
        PUBLIC_BASE_URL: base, OAUTH_ISSUER: oauth ? base : "", OAUTH_STORE_PATH: join(dataDir, "oauth.json"),
        NANGO_SECRET_KEY: "test-only-key", NANGO_GCALENDAR_INTEGRATION_ID: "calendar-test",
        GOOGLE_CONNECTOR_ORG_ID: "acme", GOOGLE_CONNECTOR_PILOT_SUBJECTS: "",
        OAUTH_CONSENT_PASSWORD: "test-control-password", MCP_SESSION_SECRET: "test-stable-session-secret-with-32-bytes",
        MCP_BEARER_TOKEN: "shared-test-bearer" },
    });
    let diagnostics = "";
    child.stdout.resume(); child.stderr.on("data", (chunk) => { diagnostics = (diagnostics + chunk.toString()).slice(-8000); });
    try {
      let health;
      for (let i = 0; i < 100; i++) {
        try { health = await fetch(base + "/health"); break; } catch { await new Promise((resolve) => setTimeout(resolve, 30)); }
      }
      assert.ok(health, `Gateway did not start: ${diagnostics}`); assert.equal(health.status, oauth ? 200 : 503);
      for (const headers of [{}, { Authorization: "Bearer shared-test-bearer", "x-agent-id": "forged-client" }]) {
        const response = await fetch(base + "/mcp", { method: "POST", headers: { "Content-Type": "application/json", ...headers },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } }) });
        assert.equal(response.status, 401);
      }
    } finally {
      if (child.exitCode === null) { child.kill("SIGTERM"); await once(child, "exit"); }
      rmSync(dataDir, { recursive: true, force: true });
    }
  });
}

#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const args = parseArgs(process.argv.slice(2));
const outDir = args.out ?? join("artifacts", "mcp-demo", new Date().toISOString().replace(/[:.]/g, "-"));
mkdirSync(outDir, { recursive: true });

async function main() {
  const client = new McpClient({ outDir });
  await client.start();
  try {
    const initialize = await client.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: {
        name: "turnstile-mcp-agent-demo",
        title: "TURNSTILE MCP Agent Demo",
        version: "0.1.0"
      }
    });
    client.notify("notifications/initialized", {});

    const tools = await client.request("tools/list", {});
    const resourcesBefore = await client.request("resources/list", {});
    const actionRegistry = await client.request("resources/read", { uri: "strata://action-registry/current" });
    const toolName = "strata.verified.payment.create";
    const tool = tools.tools.find((item) => item.name === toolName);
    if (!tool) {
      throw new Error(`MCP server did not expose ${toolName}`);
    }

    const call = await client.request("tools/call", {
      name: toolName,
      arguments: {
        amount: Number(args.amount ?? 1250),
        currency: args.currency ?? "USD",
        recipient: args.recipient ?? "vendor_123"
      }
    });
    const resourcesAfter = await client.request("resources/list", {});
    const latestCertificate = await client.request("resources/read", { uri: "strata://certificate/latest" });
    const structured = call.structuredContent;

    const summary = {
      ok: structured?.verified === true,
      outDir,
      server: initialize.serverInfo,
      server_capabilities: initialize.capabilities,
      discovered_tools: tools.tools.map((item) => ({
        name: item.name,
        title: item.title,
        required: item.inputSchema?.required ?? []
      })),
      resources_before: resourcesBefore.resources.map((item) => item.uri),
      resources_after: resourcesAfter.resources.map((item) => item.uri),
      action_registry_resource: JSON.parse(actionRegistry.contents[0].text),
      tool_called: toolName,
      tool_result: structured,
      certificate_resource: JSON.parse(latestCertificate.contents[0].text)
    };

    writeFileSync(join(outDir, "mcp-agent-summary.json"), `${JSON.stringify(summary, null, 2)}\n`, "utf8");
    console.log(JSON.stringify({
      ok: summary.ok,
      outDir,
      discovered_tools: summary.discovered_tools.map((item) => item.name),
      tool_called: toolName,
      witness_quorum: structured.witness_quorum,
      certificate_verified: structured.verified,
      certificate_ref: structured.certificate_ref,
      receipt_count: structured.receipt_count,
      checkpoint_id: structured.checkpoint_id
    }, null, 2));
    process.exitCode = summary.ok ? 0 : 1;
  } finally {
    await client.stop();
  }
}

class McpClient {
  constructor({ outDir }) {
    this.outDir = outDir;
    this.nextId = 1;
    this.pending = new Map();
    this.buffer = "";
    this.stderr = "";
  }

  async start() {
    this.child = spawn(process.execPath, ["bin/turnstile-mcp-server.js", "--out", this.outDir], {
      cwd: process.cwd(),
      stdio: ["pipe", "pipe", "pipe"]
    });

    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (chunk) => this.handleStdout(chunk));
    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (chunk) => {
      this.stderr += chunk;
    });
    this.child.on("exit", (code) => {
      for (const { reject } of this.pending.values()) {
        reject(new Error(`MCP server exited with code ${code}: ${this.stderr}`));
      }
      this.pending.clear();
    });
  }

  request(method, params) {
    const id = this.nextId;
    this.nextId += 1;
    const message = { jsonrpc: "2.0", id, method, params };
    this.child.stdin.write(`${JSON.stringify(message)}\n`);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Timed out waiting for MCP response to ${method}. stderr=${this.stderr}`));
      }, 30000);
      this.pending.set(id, { resolve, reject, timer });
    });
  }

  notify(method, params) {
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
  }

  handleStdout(chunk) {
    this.buffer += chunk;
    for (;;) {
      const newline = this.buffer.indexOf("\n");
      if (newline === -1) {
        break;
      }
      const line = this.buffer.slice(0, newline).trim();
      this.buffer = this.buffer.slice(newline + 1);
      if (!line) {
        continue;
      }
      const message = JSON.parse(line);
      const pending = this.pending.get(message.id);
      if (!pending) {
        continue;
      }
      clearTimeout(pending.timer);
      this.pending.delete(message.id);
      if (message.error) {
        pending.reject(new Error(`${message.error.message}${message.error.data ? ` ${JSON.stringify(message.error.data)}` : ""}`));
      } else {
        pending.resolve(message.result);
      }
    }
  }

  stop() {
    return new Promise((resolve) => {
      if (!this.child || this.child.exitCode !== null) {
        resolve();
        return;
      }
      this.child.once("exit", () => resolve());
      this.child.stdin.end();
      setTimeout(() => {
        if (this.child.exitCode === null) {
          this.child.kill("SIGTERM");
        }
        resolve();
      }, 1000);
    });
  }
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) {
      continue;
    }
    parsed[item.slice(2)] = argv[index + 1] ?? "true";
    if (argv[index + 1] && !argv[index + 1].startsWith("--")) {
      index += 1;
    }
  }
  return parsed;
}

await main();

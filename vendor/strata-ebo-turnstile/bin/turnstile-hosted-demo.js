#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

loadDotEnv();

const args = parseArgs(process.argv.slice(2));
const tinfoilOrg = requiredEnv("TINFOIL_ORG");
const configTag = args["config-tag"] ?? process.env.CONFIG_TAG ?? "v0.1.0-tinfoil-demo.2";
const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
const outDir = args.out ?? join("artifacts", "hosted-demo", timestamp);
const skipReset = truthy(args["skip-reset"]);

const targets = {
  gateway: target({
    name: "gateway",
    url: process.env.TINFOIL_GATEWAY_URL || `https://turnstile-gateway.${tinfoilOrg}.containers.tinfoil.dev`,
    repo: requiredEnv("TINFOIL_GATEWAY_CONFIG_REPO"),
    keyPath: "/v1/keyring"
  }),
  w1: target({
    name: "w1",
    url: process.env.TINFOIL_WITNESS_1_URL || `https://turnstile-witness-1.${tinfoilOrg}.containers.tinfoil.dev`,
    repo: requiredEnv("TINFOIL_WITNESS_1_CONFIG_REPO"),
    keyPath: "/v1/public-key"
  }),
  w2: target({
    name: "w2",
    url: process.env.TINFOIL_WITNESS_2_URL || `https://turnstile-witness-2.${tinfoilOrg}.containers.tinfoil.dev`,
    repo: requiredEnv("TINFOIL_WITNESS_2_CONFIG_REPO"),
    keyPath: "/v1/public-key"
  }),
  w3: target({
    name: "w3",
    url: process.env.TINFOIL_WITNESS_3_URL || `https://turnstile-witness-3.${tinfoilOrg}.containers.tinfoil.dev`,
    repo: requiredEnv("TINFOIL_WITNESS_3_CONFIG_REPO"),
    keyPath: "/v1/public-key"
  })
};

mkdirSync(outDir, { recursive: true });

const attestations = {};
const publicKeys = {};
for (const [name, item] of Object.entries(targets)) {
  attestations[name] = tinfoilJson(["attestation", "verify", "-e", item.host, "-r", item.repo, "-j"]);
  writeJson(join(outDir, `attestation-${name}.json`), attestations[name]);
  publicKeys[name] = tinfoilHttp("get", item, item.keyPath);
  writeJson(join(outDir, `public-key-${name}.json`), publicKeys[name]);
}

const gateway = targets.gateway;
const health = tinfoilHttp("get", gateway, "/health");
const egressPolicy = tinfoilHttp("get", gateway, "/v1/egress-policy").egress_policy;
writeJson(join(outDir, "health.json"), health);
writeJson(join(outDir, "egress-policy.json"), egressPolicy);

let reset = null;
if (!skipReset) {
  reset = tinfoilHttp("post", gateway, "/v1/demo/reset", {});
  writeJson(join(outDir, "reset.json"), reset);
} else {
  const existing = tinfoilHttp("get", gateway, "/v1/receipts").receipts ?? [];
  if (existing.length > 0) {
    throw new Error(
      `--skip-reset requires an empty gateway, but ${existing.length} existing receipts were found. `
      + "Run `npm run demo:hosted` without --skip-reset for repeatable demos."
    );
  }
}

const sessionId = args["session-id"] ?? `sess_tinfoil_demo_${Date.now()}`;
const session = tinfoilHttp("post", gateway, "/v1/sessions", {
  sessionId,
  taskInputDigest: sha256Hex("pay approved invoice INV-123")
});
const model = tinfoilHttp("post", gateway, "/v1/actions", {
  type: "model.call",
  prompt: "Decide whether invoice INV-123 should be paid",
  model: "mock.local"
});
const data = tinfoilHttp("post", gateway, "/v1/actions", {
  type: "data.query",
  source: "payments-ledger",
  query: "select payment status for INV-123"
});
const tool = tinfoilHttp("post", gateway, "/v1/actions", {
  type: "tool.call",
  toolName: "payments-api",
  method: "POST /v1/payments",
  request: { amount: 1250, currency: "USD", recipient: "vendor_123" }
});
const end = tinfoilHttp("post", gateway, "/v1/sessions/end", { reason: "complete" });
const checkpoint = tinfoilHttp("post", gateway, "/v1/checkpoints", {});

const receipts = tinfoilHttp("get", gateway, "/v1/receipts").receipts;
const transparencyLog = tinfoilHttp("get", gateway, "/v1/transparency-log").entries;
const keyring = tinfoilHttp("get", gateway, "/v1/keyring").keyring;

writeJson(join(outDir, "run-summary.json"), { sessionId, session, model, data, tool, end, checkpoint });
writeJson(join(outDir, "keyring.json"), keyring);
writeJson(join(outDir, "checkpoint.json"), checkpoint.checkpoint);
writeJsonl(join(outDir, "receipts.jsonl"), receipts);
writeJsonl(join(outDir, "transparency-log.jsonl"), transparencyLog);

const verifyArgs = [
  "bin/turnstile-verify.js",
  "--log", join(outDir, "receipts.jsonl"),
  "--keyring", join(outDir, "keyring.json"),
  "--checkpoint", join(outDir, "checkpoint.json"),
  "--transparency-log", join(outDir, "transparency-log.jsonl"),
  "--strict", "true",
  "--require-tinfoil-attestation", "true",
  "--require-tinfoil-config-policy", "true",
  "--tinfoil-target", targetArg(targets.gateway),
  "--tinfoil-config", `gateway=https://raw.githubusercontent.com/${targets.gateway.repo}/${configTag}/tinfoil-config.yml`,
  "--tinfoil-target", targetArg(targets.w1),
  "--tinfoil-target", targetArg(targets.w2),
  "--tinfoil-target", targetArg(targets.w3)
];
const verificationProcess = spawnSync(process.execPath, verifyArgs, {
  encoding: "utf8",
  maxBuffer: 50 * 1024 * 1024
});
if (verificationProcess.status !== 0) {
  writeFileSync(join(outDir, "verification.stdout"), verificationProcess.stdout ?? "", "utf8");
  writeFileSync(join(outDir, "verification.stderr"), verificationProcess.stderr ?? "", "utf8");
  throw new Error(`strict verification failed; see ${outDir}/verification.*`);
}
writeFileSync(join(outDir, "verification.json"), verificationProcess.stdout, "utf8");
const verification = JSON.parse(verificationProcess.stdout);

const summary = {
  ok: verification.ok,
  outDir,
  sessionId,
  receipt_count: receipts.length,
  transparency_entries: transparencyLog.length,
  checkpoint_id: checkpoint.checkpoint.statement.checkpoint_id,
  gateway: gateway.url,
  witnesses: [targets.w1.url, targets.w2.url, targets.w3.url],
  egress_policy: egressPolicy,
  tinfoil_targets: verification.tinfoil.targets.map((item) => ({
    name: item.name,
    ok: item.ok,
    status: item.tinfoil_verification?.json?.status ?? item.tinfoil_verification?.status,
    host: item.host
  }))
};
writeJson(join(outDir, "summary.json"), summary);
console.log(JSON.stringify(summary, null, 2));
process.exitCode = summary.ok ? 0 : 1;

function target({ name, url, repo, keyPath }) {
  const normalized = url.replace(/\/$/, "");
  return { name, url: normalized, repo, keyPath, host: new URL(normalized).host };
}

function targetArg(item) {
  return `${item.name}=${item.url},${item.repo},${item.keyPath}`;
}

function tinfoilHttp(method, item, path, body = undefined) {
  const args = ["http", method, `${item.url}${path}`, "-e", item.host, "-r", item.repo];
  if (body !== undefined) {
    args.push("-b", JSON.stringify(body));
  }
  const value = tinfoilJson(args);
  if (value && typeof value === "object" && typeof value.error === "string") {
    throw new Error(`Tinfoil HTTP ${method.toUpperCase()} ${path} returned error: ${value.error}`);
  }
  return value;
}

function tinfoilJson(commandArgs) {
  const result = spawnSync("tinfoil", commandArgs, {
    encoding: "utf8",
    maxBuffer: 50 * 1024 * 1024
  });
  if (result.status !== 0) {
    throw new Error(`tinfoil ${commandArgs.join(" ")} failed: ${result.stderr || result.stdout}`);
  }
  return JSON.parse(result.stdout);
}

function writeJson(filePath, value) {
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function writeJsonl(filePath, values) {
  writeFileSync(filePath, `${values.map((value) => JSON.stringify(value)).join("\n")}\n`, "utf8");
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function requiredEnv(name) {
  if (!process.env[name]) {
    throw new Error(`${name} is required`);
  }
  return process.env[name];
}

function loadDotEnv() {
  if (!existsSync(".env")) {
    return;
  }
  for (const line of readFileSync(".env", "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const equals = trimmed.indexOf("=");
    if (equals === -1) {
      continue;
    }
    const key = trimmed.slice(0, equals).trim();
    const value = stripQuotes(trimmed.slice(equals + 1).trim());
    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

function stripQuotes(value) {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
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

function truthy(value) {
  return value === true || value === "true" || value === "1" || value === "yes";
}

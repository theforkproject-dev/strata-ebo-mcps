#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const DEFAULT_SECRETS = [
  "MCP_SESSION_SECRET",
  "RESEND_API_KEY",
  "OAUTH_CONSENT_PASSWORD_SHA256",
  "OAUTH_DYNAMODB_AWS_ACCESS_KEY_ID",
  "OAUTH_DYNAMODB_AWS_SECRET_ACCESS_KEY",
  "CERTIFICATE_BUNDLE_AWS_ACCESS_KEY_ID",
  "CERTIFICATE_BUNDLE_AWS_SECRET_ACCESS_KEY",
  "GATEWAY_KEY_JSON",
  "OPERATOR_ADMISSION_KEY_JSON"
];

const DEFAULTS = {
  sourceDir: ROOT,
  configDir: "/tmp/strata-email-mcp-gateway",
  configRepo: "theforkproject-dev/strata-email-mcp-gateway",
  imageRepo: "ghcr.io/theforkproject-dev/strata-ebo-mcps",
  containerId: "027bacb5-3cdd-45b7-979e-02966162abd6",
  containerHost: "strata-email-mcp-gateway.amotivv.containers.tinfoil.dev",
  workflowName: "Build and Attest",
  platform: "linux/amd64",
  healthPath: "/health",
  tinfoilApiUrl: "https://api.tinfoil.sh",
  tinfoilCli: process.env.TINFOIL_CLI || "tinfoil"
};

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const options = {
    ...DEFAULTS,
    ...args,
    configFile: resolve(args.configDir || DEFAULTS.configDir, "tinfoil-config.yml"),
    apply: Boolean(args.apply),
    build: args.build !== false,
    updateConfig: args.updateConfig !== false,
    commit: args.commit !== false,
    waitRelease: args.waitRelease !== false,
    relaunch: args.relaunch !== false,
    verify: args.verify !== false,
    secrets: args.secrets?.length ? args.secrets : DEFAULT_SECRETS
  };

  validateOptions(options);

  const plan = [
    `source repo: ${options.sourceDir}`,
    `config repo: ${options.configDir}`,
    `config tag: ${options.tag}`,
    `image tag: ${options.imageRepo}:${options.imageTag}`,
    `build/push image: ${options.build}`,
    `update config: ${options.updateConfig}`,
    `commit/tag/push config: ${options.commit}`,
    `wait for Tinfoil release assets: ${options.waitRelease}`,
    `relaunch container: ${options.relaunch}`,
    `verify health/attestation: ${options.verify}`
  ];
  console.log(`Tinfoil gateway deploy plan:\n- ${plan.join("\n- ")}`);

  if (!options.apply) {
    console.log("\nDry run only. Re-run with --apply to mutate Docker/GitHub/Tinfoil.");
    return;
  }

  ensureCleanGit(options.configDir, "config repo", options.allowDirtyConfig);
  ensureSourceCleanIfRequested(options);

  const imageDigest = options.imageDigest || await resolveImageDigest(options);
  const imageRef = `${options.imageRepo}:${options.imageTag}@${imageDigest}`;

  if (options.updateConfig) {
    updateTinfoilConfig(options, { imageRef, imageDigest });
  }

  if (options.commit) {
    commitAndPushConfig(options);
  }

  if (options.waitRelease) {
    await waitForReleaseAssets(options);
  }

  if (options.relaunch) {
    await relaunchContainer(options);
    await waitForContainerReady(options);
  }

  if (options.verify) {
    await verifyHealth(options);
    verifyAttestation(options);
  }

  console.log("Tinfoil gateway deploy helper completed successfully.");
}

function parseArgs(argv) {
  const options = { secrets: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") options.help = true;
    else if (arg === "--apply") options.apply = true;
    else if (arg === "--skip-build") options.build = false;
    else if (arg === "--skip-config") options.updateConfig = false;
    else if (arg === "--skip-commit") options.commit = false;
    else if (arg === "--skip-release-wait") options.waitRelease = false;
    else if (arg === "--skip-relaunch") options.relaunch = false;
    else if (arg === "--skip-verify") options.verify = false;
    else if (arg === "--allow-dirty-source") options.allowDirtySource = true;
    else if (arg === "--allow-dirty-config") options.allowDirtyConfig = true;
    else if (arg === "--tag") options.tag = takeValue(argv, ++i, arg);
    else if (arg === "--image-tag") options.imageTag = takeValue(argv, ++i, arg);
    else if (arg === "--image-digest") options.imageDigest = normalizeDigest(takeValue(argv, ++i, arg));
    else if (arg === "--source-dir") options.sourceDir = resolve(takeValue(argv, ++i, arg));
    else if (arg === "--config-dir") options.configDir = resolve(takeValue(argv, ++i, arg));
    else if (arg === "--config-repo") options.configRepo = takeValue(argv, ++i, arg);
    else if (arg === "--image-repo") options.imageRepo = takeValue(argv, ++i, arg);
    else if (arg === "--container-id") options.containerId = takeValue(argv, ++i, arg);
    else if (arg === "--container-host") options.containerHost = takeValue(argv, ++i, arg);
    else if (arg === "--workflow") options.workflowName = takeValue(argv, ++i, arg);
    else if (arg === "--platform") options.platform = takeValue(argv, ++i, arg);
    else if (arg === "--health-path") options.healthPath = takeValue(argv, ++i, arg);
    else if (arg === "--tinfoil-api-url") options.tinfoilApiUrl = takeValue(argv, ++i, arg).replace(/\/$/, "");
    else if (arg === "--tinfoil-cli") options.tinfoilCli = takeValue(argv, ++i, arg);
    else if (arg === "--secret") options.secrets.push(takeValue(argv, ++i, arg));
    else if (arg === "--commit-message") options.commitMessage = takeValue(argv, ++i, arg);
    else if (arg === "--cache-bust") options.cacheBust = takeValue(argv, ++i, arg);
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return options;
}

function takeValue(argv, index, flag) {
  const value = argv[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function validateOptions(options) {
  if (!options.tag) {
    throw new Error("--tag is required, for example --tag v0.1.0-email-gateway.14");
  }
  if (!options.imageTag) {
    throw new Error("--image-tag is required, for example --image-tag tinfoil-email-gateway-011");
  }
  if (!existsSync(options.sourceDir)) {
    throw new Error(`source directory does not exist: ${options.sourceDir}`);
  }
  if (!existsSync(options.configFile)) {
    throw new Error(`tinfoil config file does not exist: ${options.configFile}`);
  }
}

async function resolveImageDigest(options) {
  if (options.build) {
    run("docker", [
      "buildx",
      "build",
      "--platform",
      options.platform,
      "-t",
      `${options.imageRepo}:${options.imageTag}`,
      "--build-arg",
      `CACHE_BUST=${options.cacheBust || `${options.tag}-${Date.now()}`}`,
      "--push",
      "."
    ], { cwd: options.sourceDir });
  }
  const inspect = run("docker", ["buildx", "imagetools", "inspect", `${options.imageRepo}:${options.imageTag}`], {
    cwd: options.sourceDir,
    capture: true
  });
  const digest = inspect.match(/Digest:\s+(sha256:[a-f0-9]{64})/i)?.[1];
  if (!digest) {
    throw new Error(`Could not parse image digest from docker imagetools output for ${options.imageRepo}:${options.imageTag}`);
  }
  return digest;
}

function updateTinfoilConfig(options, { imageRef, imageDigest }) {
  const before = readFileSync(options.configFile, "utf8");
  let after = before;
  after = replaceYamlValue(after, "image", imageRef);
  after = replaceEnvValue(after, "GATEWAY_TINFOIL_CONFIG_TAG", options.tag);
  after = replaceEnvValue(after, "GATEWAY_TINFOIL_IMAGE_DIGEST", imageDigest);
  after = ensureSecretNames(after, options.secrets);
  if (after === before) {
    console.log("No tinfoil-config.yml changes needed.");
    return;
  }
  writeFileSync(options.configFile, after);
  run("git", ["diff", "--", "tinfoil-config.yml"], { cwd: options.configDir });
}

function replaceYamlValue(text, key, value) {
  const pattern = new RegExp(`(^\\s*${escapeRegex(key)}:\\s*)"[^"]*"`, "m");
  if (!pattern.test(text)) {
    throw new Error(`Could not find YAML key ${key}`);
  }
  return text.replace(pattern, `$1"${value}"`);
}

function replaceEnvValue(text, key, value) {
  const pattern = new RegExp(`(^\\s*-\\s*${escapeRegex(key)}:\\s*)"[^"]*"`, "m");
  if (!pattern.test(text)) {
    throw new Error(`Could not find env key ${key}`);
  }
  return text.replace(pattern, `$1"${value}"`);
}

function ensureSecretNames(text, secrets) {
  let output = text;
  for (const secret of secrets) {
    if (new RegExp(`^\\s*-\\s*${escapeRegex(secret)}\\s*$`, "m").test(output)) {
      continue;
    }
    output = output.replace(/(\n\s*command:\s*\[)/, `\n      - ${secret}$1`);
  }
  return output;
}

function commitAndPushConfig(options) {
  const changed = run("git", ["status", "--short", "--", "tinfoil-config.yml"], {
    cwd: options.configDir,
    capture: true
  }).trim();
  if (!changed) {
    console.log("No config changes to commit.");
  } else {
    run("git", ["add", "tinfoil-config.yml"], { cwd: options.configDir });
    run("git", ["commit", "-m", options.commitMessage || `feat: deploy email gateway ${options.tag}`], { cwd: options.configDir });
  }
  const existingTag = run("git", ["tag", "--list", options.tag], { cwd: options.configDir, capture: true }).trim();
  if (!existingTag) {
    run("git", ["tag", options.tag], { cwd: options.configDir });
  }
  run("git", ["push", "origin", "HEAD"], { cwd: options.configDir });
  run("git", ["push", "origin", options.tag], { cwd: options.configDir });
}

async function waitForReleaseAssets(options) {
  const deadline = Date.now() + 10 * 60 * 1000;
  let last = "";
  while (Date.now() < deadline) {
    const result = spawnSync("gh", [
      "release",
      "view",
      options.tag,
      "-R",
      options.configRepo,
      "--json",
      "assets,isDraft,isPrerelease,publishedAt,url"
    ], { encoding: "utf8" });
    if (result.status === 0) {
      const release = JSON.parse(result.stdout);
      const assetNames = new Set((release.assets || []).map((asset) => asset.name));
      if (assetNames.has("tinfoil-deployment.json") && assetNames.has("tinfoil.hash")) {
        console.log(`Release assets ready: ${release.url}`);
        return;
      }
      last = `release exists without required assets: ${[...assetNames].join(", ")}`;
    } else {
      last = result.stderr.trim() || result.stdout.trim();
    }
    await sleep(5000);
  }
  run("gh", ["run", "list", "-R", options.configRepo, "--limit", "5"], { cwd: options.configDir });
  throw new Error(`Timed out waiting for Tinfoil release assets for ${options.tag}: ${last}`);
}

async function relaunchContainer(options) {
  const token = process.env.TINFOIL_API_KEY;
  if (!token) {
    throw new Error("TINFOIL_API_KEY is required for relaunch");
  }
  const response = await fetch(`${options.tinfoilApiUrl}/api/containers/${options.containerId}/relaunch`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({ tag: options.tag, secrets: options.secrets })
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Tinfoil relaunch failed: ${response.status} ${text}`);
  }
  console.log(`Tinfoil relaunch accepted: ${summarizeJson(text)}`);
}

async function waitForContainerReady(options) {
  const token = process.env.TINFOIL_API_KEY;
  const deadline = Date.now() + 10 * 60 * 1000;
  let last = null;
  while (Date.now() < deadline) {
    const response = await fetch(`${options.tinfoilApiUrl}/api/containers/${options.containerId}`, {
      headers: { authorization: `Bearer ${token}` }
    });
    if (!response.ok) {
      throw new Error(`Tinfoil container get failed: ${response.status} ${await response.text()}`);
    }
    const container = await response.json();
    last = container;
    console.log(JSON.stringify({ status: container.status, current_tag: container.current_tag, update_tag: container.update_tag, update_status: container.update_status, error_message: container.error_message }));
    if (container.status === "ready" && container.current_tag === options.tag && !container.update_tag) {
      for (const secret of options.secrets) {
        if (!container.secrets?.includes(secret)) {
          throw new Error(`Container is ready but missing secret binding ${secret}`);
        }
      }
      return container;
    }
    await sleep(10000);
  }
  throw new Error(`Timed out waiting for Tinfoil container readiness: ${JSON.stringify({ status: last?.status, current_tag: last?.current_tag, update_tag: last?.update_tag, update_status: last?.update_status, error_message: last?.error_message })}`);
}

async function verifyHealth(options) {
  const url = `https://${options.containerHost}${options.healthPath}`;
  const response = await fetch(url);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Health check failed: ${response.status} ${text}`);
  }
  console.log(`Health ok: ${text}`);
}

function verifyAttestation(options) {
  run(options.tinfoilCli, [
    "-e",
    options.containerHost,
    "-r",
    options.configRepo,
    "attestation",
    "verify",
    "-j"
  ], { cwd: options.configDir });
}

function ensureCleanGit(cwd, label, allowDirty) {
  const status = run("git", ["status", "--short"], { cwd, capture: true }).trim();
  if (status && !allowDirty) {
    throw new Error(`${label} has uncommitted changes. Commit/stash them or pass --allow-dirty-config.\n${status}`);
  }
}

function ensureSourceCleanIfRequested(options) {
  const status = run("git", ["status", "--short"], { cwd: options.sourceDir, capture: true }).trim();
  if (status && !options.allowDirtySource) {
    throw new Error(`source repo has uncommitted changes. Commit/stash them or pass --allow-dirty-source.\n${status}`);
  }
}

function run(command, args, { cwd = ROOT, capture = false } = {}) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit"
  });
  if (result.status !== 0) {
    const output = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
    throw new Error(`${command} ${args.join(" ")} failed${output ? `:\n${output}` : ""}`);
  }
  return result.stdout || "";
}

function summarizeJson(text) {
  try {
    const data = JSON.parse(text);
    return JSON.stringify({ id: data.id, name: data.name, current_tag: data.current_tag, update_tag: data.update_tag, status: data.status });
  } catch {
    return text.slice(0, 200);
  }
}

function normalizeDigest(value) {
  return value.startsWith("sha256:") ? value : `sha256:${value}`;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function printHelp() {
  console.log(`Usage:
  npm run deploy:tinfoil-gateway -- --tag v0.1.0-email-gateway.14 --image-tag tinfoil-email-gateway-011 --apply

Default behavior is dry-run. Pass --apply to mutate Docker, GitHub, and Tinfoil.

Required:
  --tag <tag>                 Tinfoil config tag/release to deploy
  --image-tag <tag>           GHCR image tag to build/inspect

Common options:
  --skip-build                Reuse an already-pushed image tag
  --image-digest <sha256>     Use a known image digest instead of inspecting
  --skip-relaunch             Stop after config tag/release assets are ready
  --allow-dirty-source        Allow building from uncommitted source changes
  --allow-dirty-config        Allow starting with a dirty config checkout
  --tinfoil-cli <path>        CLI for attestation verify (default: TINFOIL_CLI or tinfoil)

Important:
  The script never creates GitHub releases manually. It pushes the tag and waits
  for the config repo's Build and Attest workflow to create tinfoil.hash and
  tinfoil-deployment.json. Relaunch uses the Tinfoil API with the full secret
  reference list so new secret bindings are not silently omitted.
`);
}

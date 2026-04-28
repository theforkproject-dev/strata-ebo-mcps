import { spawnSync } from "node:child_process";
import { sha256Hex } from "./crypto.js";

const DEFAULT_TIMEOUT_MS = 30000;

export function parseTinfoilTargets(values = [], configValues = []) {
  const configs = new Map(configValues.map((value) => {
    const [name, configUrl] = splitOnce(value, "=");
    if (!name || !configUrl) {
      throw new Error(`Invalid --tinfoil-config value: ${value}`);
    }
    return [name, configUrl];
  }));

  return values.map((value) => {
    const [name, rest] = splitOnce(value, "=");
    if (!name || !rest) {
      throw new Error(`Invalid --tinfoil-target value: ${value}`);
    }

    const [url, repo, keyPath] = rest.split(",").map((item) => item.trim());
    if (!url) {
      throw new Error(`Tinfoil target ${name} is missing a URL`);
    }
    if (!repo) {
      throw new Error(`Tinfoil target ${name} is missing a config repo`);
    }

    return {
      name,
      url: normalizeUrl(url),
      repo,
      keyPath: keyPath || defaultKeyPath(name),
      configUrl: configs.get(name) ?? null
    };
  });
}

export async function verifyTinfoilTargets({
  targets,
  keyring,
  admissionManifest = null,
  require = false,
  requireConfigPolicy = false,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  tinfoilBin = process.env.TINFOIL_CLI ?? "tinfoil"
}) {
  const errors = [];
  const warnings = [];
  const results = [];
  const gatewayPolicy = admissionManifest?.gateway_evidence?.egress_policy ?? null;

  if (require && targets.length === 0) {
    errors.push("Tinfoil attestation targets are required but none were provided");
  }

  if (requireConfigPolicy && !gatewayPolicy) {
    errors.push("gateway egress policy is required but missing from admission manifest");
  }

  for (const target of targets) {
    const result = await verifyTinfoilTarget({
      target,
      keyring,
      gatewayPolicy,
      requireConfigPolicy,
      timeoutMs,
      tinfoilBin
    });
    results.push(result);
    errors.push(...result.errors.map((error) => `${target.name}: ${error}`));
    warnings.push(...result.warnings.map((warning) => `${target.name}: ${warning}`));
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    egress_policy: gatewayPolicy,
    targets: results
  };
}

async function verifyTinfoilTarget({ target, keyring, gatewayPolicy, requireConfigPolicy, timeoutMs, tinfoilBin }) {
  const errors = [];
  const warnings = [];
  const host = new URL(target.url).host;
  const attestationUrl = new URL("/.well-known/tinfoil-attestation", target.url).toString();
  let attestationDocument = null;
  let tinfoilVerification = null;
  let keyBinding = null;
  let configPolicy = null;

  try {
    attestationDocument = await fetchAttestationDocument(attestationUrl, timeoutMs);
    errors.push(...attestationDocument.errors.map((error) => `attestation document: ${error}`));
  } catch (error) {
    errors.push(`failed to fetch attestation document: ${error.message}`);
  }

  const verify = runCommand(tinfoilBin, ["attestation", "verify", "-e", host, "-r", target.repo, "-j"]);
  if (!verify.ok) {
    errors.push(`tinfoil attestation verify failed: ${verify.error}`);
  }
  tinfoilVerification = verify;

  if (target.keyPath) {
    const keyUrl = new URL(target.keyPath, target.url).toString();
    const keyResponse = runCommand(tinfoilBin, ["http", "get", keyUrl, "-e", host, "-r", target.repo]);
    if (!keyResponse.ok) {
      errors.push(`failed to fetch public key through Tinfoil verifier path: ${keyResponse.error}`);
      keyBinding = keyResponse;
    } else {
      keyBinding = compareKeyResponse(target, keyResponse, keyring);
      errors.push(...keyBinding.errors);
      warnings.push(...keyBinding.warnings);
    }
  }

  if (target.configUrl) {
    configPolicy = await verifyConfigPolicy({
      configUrl: target.configUrl,
      gatewayPolicy,
      requireConfigPolicy,
      timeoutMs
    });
    errors.push(...configPolicy.errors);
    warnings.push(...configPolicy.warnings);
  } else if (requireConfigPolicy && target.name === "gateway") {
    errors.push("gateway Tinfoil config URL is required to verify egress policy in measured config");
  }

  return {
    name: target.name,
    url: target.url,
    host,
    repo: target.repo,
    attestation_url: attestationUrl,
    attestation_document: attestationDocument,
    tinfoil_verification: tinfoilVerification,
    key_binding: keyBinding,
    config_policy: configPolicy,
    ok: errors.length === 0,
    errors,
    warnings
  };
}

async function fetchAttestationDocument(url, timeoutMs) {
  const response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  const document = await response.json();
  const errors = [];
  if (typeof document.format !== "string" || document.format.length === 0) {
    errors.push("format must be a non-empty string");
  }
  if (typeof document.body !== "string" || document.body.length === 0) {
    errors.push("body must be a non-empty base64 string");
  }
  return {
    ok: errors.length === 0,
    errors,
    format: document.format,
    body_sha256: sha256Hex(document.body)
  };
}

function compareKeyResponse(target, commandResult, keyring) {
  const errors = [];
  const warnings = [];
  let body = null;
  try {
    body = JSON.parse(commandResult.stdout);
  } catch (error) {
    return {
      ...commandResult,
      ok: false,
      errors: [`public key endpoint did not return JSON: ${error.message}`],
      warnings,
      response: null
    };
  }

  if (body.keyring && typeof body.keyring === "object") {
    for (const [keyId, publicKeyPem] of Object.entries(body.keyring)) {
      if (!keyring[keyId]) {
        errors.push(`attested keyring contains ${keyId}, but local verifier keyring does not`);
      } else if (normalizePem(keyring[keyId]) !== normalizePem(publicKeyPem)) {
        errors.push(`attested keyring value for ${keyId} does not match local verifier keyring`);
      }
    }
  } else if (body.key_id && body.public_key_pem) {
    if (!keyring[body.key_id]) {
      errors.push(`attested ${target.name} key ${body.key_id} is missing from local verifier keyring`);
    } else if (normalizePem(keyring[body.key_id]) !== normalizePem(body.public_key_pem)) {
      errors.push(`attested ${target.name} key ${body.key_id} does not match local verifier keyring`);
    }
  } else {
    errors.push("public key endpoint must return either {key_id, public_key_pem} or {keyring}");
  }

  return {
    ...commandResult,
    ok: errors.length === 0,
    errors,
    warnings,
    response: redactPrivateFields(body)
  };
}

async function verifyConfigPolicy({ configUrl, gatewayPolicy, requireConfigPolicy, timeoutMs }) {
  const errors = [];
  const warnings = [];
  let response;
  try {
    response = await fetch(configUrl, { signal: AbortSignal.timeout(timeoutMs) });
  } catch (error) {
    return {
      ok: false,
      errors: [`failed to fetch Tinfoil config: ${error.message}`],
      warnings,
      config_url: configUrl
    };
  }
  if (!response.ok) {
    return {
      ok: false,
      errors: [`failed to fetch Tinfoil config: HTTP ${response.status}`],
      warnings,
      config_url: configUrl
    };
  }

  const configText = await response.text();
  if (gatewayPolicy) {
    if (!configText.includes("EGRESS_POLICY_MODE")) {
      errors.push("tinfoil-config.yml does not declare EGRESS_POLICY_MODE");
    }
    if (gatewayPolicy.mode && !configText.includes(gatewayPolicy.mode)) {
      errors.push(`tinfoil-config.yml does not contain expected egress policy mode ${gatewayPolicy.mode}`);
    }
    for (const url of gatewayPolicy.allowed_urls ?? []) {
      if (!configText.includes(url)) {
        errors.push(`tinfoil-config.yml does not contain allowed witness URL ${url}`);
      }
    }
  } else if (requireConfigPolicy) {
    errors.push("admission manifest has no gateway egress policy to compare with tinfoil-config.yml");
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    config_url: configUrl,
    config_sha256: sha256Hex(configText)
  };
}

function runCommand(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024
  });

  if (result.error) {
    return {
      ok: false,
      command,
      args,
      stdout: result.stdout ?? "",
      stderr: result.stderr ?? "",
      error: result.error.message
    };
  }

  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  let json = null;
  if (stdout.trim().startsWith("{")) {
    try {
      json = JSON.parse(stdout);
    } catch {
      json = null;
    }
  }

  return {
    ok: result.status === 0,
    command,
    args,
    status: result.status,
    stdout,
    stderr,
    json,
    error: result.status === 0 ? null : (stderr.trim() || stdout.trim() || `exit ${result.status}`)
  };
}

function normalizeUrl(value) {
  return /^https?:\/\//.test(value) ? value.replace(/\/$/, "") : `https://${value.replace(/\/$/, "")}`;
}

function defaultKeyPath(name) {
  return name === "gateway" ? "/v1/keyring" : "/v1/public-key";
}

function splitOnce(value, delimiter) {
  const index = value.indexOf(delimiter);
  if (index === -1) {
    return [value, ""];
  }
  return [value.slice(0, index), value.slice(index + delimiter.length)];
}

function normalizePem(value) {
  return String(value).replace(/\s+/g, "");
}

function redactPrivateFields(value) {
  if (!value || typeof value !== "object") {
    return value;
  }
  return JSON.parse(JSON.stringify(value, (key, item) => {
    if (/private|secret|token/i.test(key)) {
      return "[redacted]";
    }
    return item;
  }));
}

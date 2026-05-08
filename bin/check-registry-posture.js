#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import {
  verifyWitnessRegistryEpoch,
  verifyWitnessRegistryPointer,
  witnessRegistryEpochDigest,
  witnessRegistryPointerDigest
} from "../src/strata/primitives.js";

const DEFAULT_GATEWAY_CONFIG = "/tmp/strata-email-mcp-gateway/tinfoil-config.yml";
const DEFAULT_L1_POINTER_URL = "https://d2oeah1vhl8c0o.cloudfront.net/registry/witness/current.json";
const DEFAULT_REGISTRY_URL = "https://strata-email-registry.fly.dev";

const args = parseArgs(process.argv.slice(2));
const gatewayConfigPath = args["gateway-config"] || process.env.GATEWAY_TINFOIL_CONFIG_FILE || DEFAULT_GATEWAY_CONFIG;
const gatewayConfig = existsSync(gatewayConfigPath) ? parseTinfoilEnv(readFileSync(gatewayConfigPath, "utf8")) : {};
const warningDays = numberArg("warning-days", 7);
const criticalDays = numberArg("critical-days", 2);
const now = new Date();

const l1PointerUrl = args["l1-pointer-url"] || process.env.L1_WITNESS_REGISTRY_POINTER_URL || gatewayConfig.L1_WITNESS_REGISTRY_POINTER_URL || gatewayConfig.WITNESS_REGISTRY_POINTER_URL || DEFAULT_L1_POINTER_URL;
const registryUrl = stripSlash(args["registry-url"] || process.env.REGISTRY_URL || gatewayConfig.REGISTRY_URL || DEFAULT_REGISTRY_URL);
const policyHash = args["policy-hash"] || process.env.POLICY_BUNDLE_DIGEST || gatewayConfig.POLICY_BUNDLE_DIGEST || "";
const workflowId = args["workflow-id"] || process.env.WITNESS_WORKFLOW_ID || gatewayConfig.WITNESS_WORKFLOW_ID || "email.send";

const report = await checkPosture();
console.log(JSON.stringify(report, null, 2));
process.exitCode = report.ok ? 0 : 1;

async function checkPosture() {
  const errors = [];
  const warnings = [];
  const l1 = await checkL1Registry({ errors, warnings });
  const email = await checkEmailRegistry({ errors, warnings });
  const alignment = checkAlignment({ l1, email, errors });
  const gateway = checkGatewayConfig({ l1, email, alignment, errors, warnings });
  return {
    ok: errors.length === 0,
    checked_at: now.toISOString(),
    errors,
    warnings,
    gateway_config: gateway,
    l1_registry: l1,
    email_registry: email,
    alignment
  };
}

async function checkL1Registry({ errors, warnings }) {
  const pointer = await fetchJson(l1PointerUrl);
  const trustAnchorsUrl = pointer.registry_trust_anchors_url || gatewayConfig.L1_WITNESS_REGISTRY_TRUST_ANCHORS_URL || gatewayConfig.WITNESS_REGISTRY_TRUST_ANCHORS_URL;
  const trustAnchors = await fetchJson(trustAnchorsUrl);
  const pointerVerification = verifyWitnessRegistryPointer(pointer, trustAnchors);
  const pointerDigest = witnessRegistryPointerDigest(pointer);
  if (!pointerVerification.ok) {
    errors.push(...pointerVerification.errors.map((error) => `L1 pointer: ${error}`));
  }

  const epoch = await fetchJson(pointer.registry_epoch_url);
  const epochVerification = verifyWitnessRegistryEpoch(epoch, trustAnchors);
  const epochDigest = witnessRegistryEpochDigest(epoch);
  if (!epochVerification.ok) {
    errors.push(...epochVerification.errors.map((error) => `L1 registry epoch: ${error}`));
  }
  if (epochDigest !== pointer.registry_epoch_digest) {
    errors.push(`L1 registry epoch digest mismatch: pointer=${pointer.registry_epoch_digest} actual=${epochDigest}`);
  }

  const timing = registryTiming(pointer, { warningDays, criticalDays });
  if (timing.expired) {
    errors.push(`L1 registry pointer expired at ${pointer.valid_until}`);
  } else if (timing.past_refresh_by) {
    warnings.push(`L1 registry pointer is past refresh_by ${pointer.refresh_by}`);
  } else if (timing.days_until_refresh !== null && timing.days_until_refresh <= warningDays) {
    warnings.push(`L1 registry pointer refresh_by is within ${warningDays} day(s): ${pointer.refresh_by}`);
  }
  if (timing.days_until_expiry !== null && timing.days_until_expiry <= criticalDays) {
    errors.push(`L1 registry pointer expiry is within ${criticalDays} day(s): ${pointer.valid_until}`);
  }

  return {
    ok: pointerVerification.ok && epochVerification.ok && epochDigest === pointer.registry_epoch_digest && !timing.expired,
    pointer_url: l1PointerUrl,
    pointer_digest: pointerDigest,
    trust_anchors_url: trustAnchorsUrl,
    epoch_id: pointer.epoch_id,
    epoch_digest: epochDigest,
    epoch_url: pointer.registry_epoch_url,
    valid_from: pointer.valid_from || null,
    valid_until: pointer.valid_until || null,
    refresh_by: pointer.refresh_by || null,
    timing,
    active_mechanical_witnesses: activeMechanicalWitnesses(epoch, { workflowId, policyHash }),
    pointer_verification: pointerVerification,
    epoch_verification: epochVerification
  };
}

async function checkEmailRegistry({ errors }) {
  const [epoch, trustAnchor] = await Promise.all([
    fetchJson(`${registryUrl}/registry/current`),
    fetchJson(`${registryUrl}/registry/public-key`)
  ]);
  const verification = verifyWitnessRegistryEpoch(epoch, { [trustAnchor.key_id]: trustAnchor.public_key_pem });
  const digest = witnessRegistryEpochDigest(epoch);
  if (!verification.ok) {
    errors.push(...verification.errors.map((error) => `email registry epoch: ${error}`));
  }
  const expectedDigest = gatewayConfig.REGISTRY_EPOCH_DIGEST || process.env.REGISTRY_EPOCH_DIGEST || "";
  const digest_matches_gateway_pin = expectedDigest ? digest === expectedDigest : null;
  if (expectedDigest && digest !== expectedDigest) {
    errors.push(`email registry digest does not match gateway pin: expected=${expectedDigest} actual=${digest}`);
  }
  const expectedTrustAnchorKeyId = gatewayConfig.REGISTRY_TRUST_ANCHOR_KEY_ID || process.env.REGISTRY_TRUST_ANCHOR_KEY_ID || "";
  const trust_anchor_matches_gateway_pin = expectedTrustAnchorKeyId ? trustAnchor.key_id === expectedTrustAnchorKeyId : null;
  if (expectedTrustAnchorKeyId && trustAnchor.key_id !== expectedTrustAnchorKeyId) {
    errors.push(`email registry trust anchor does not match gateway pin: expected=${expectedTrustAnchorKeyId} actual=${trustAnchor.key_id}`);
  }
  return {
    ok: verification.ok && digest_matches_gateway_pin !== false && trust_anchor_matches_gateway_pin !== false,
    registry_url: registryUrl,
    epoch_id: epoch.epoch_id,
    epoch_digest: digest,
    expected_epoch_digest: expectedDigest || null,
    digest_matches_gateway_pin,
    trust_anchor_key_id: trustAnchor.key_id,
    expected_trust_anchor_key_id: expectedTrustAnchorKeyId || null,
    trust_anchor_matches_gateway_pin,
    active_mechanical_witnesses: activeMechanicalWitnesses(epoch, { workflowId, policyHash }),
    verification
  };
}

function checkAlignment({ l1, email, errors }) {
  const l1Keys = l1.active_mechanical_witnesses.map((witness) => witness.key_id).sort();
  const emailKeys = email.active_mechanical_witnesses.map((witness) => witness.key_id).sort();
  const missing_from_email = l1Keys.filter((key) => !emailKeys.includes(key));
  const missing_from_l1 = emailKeys.filter((key) => !l1Keys.includes(key));
  if (missing_from_email.length > 0 || missing_from_l1.length > 0) {
    errors.push(`L1/email registry witness set mismatch: missing_from_email=${missing_from_email.join(",") || "none"} missing_from_l1=${missing_from_l1.join(",") || "none"}`);
  }
  return {
    ok: missing_from_email.length === 0 && missing_from_l1.length === 0,
    workflow_id: workflowId,
    policy_hash: policyHash || null,
    l1_witness_key_ids: l1Keys,
    email_registry_witness_key_ids: emailKeys,
    missing_from_email,
    missing_from_l1
  };
}

function checkGatewayConfig({ l1, email, alignment, errors, warnings }) {
  const witnessUrls = parseWitnessUrls(gatewayConfig.WITNESS_URLS || "");
  const threshold = Number(gatewayConfig.WITNESS_THRESHOLD || gatewayConfig.L1_WITNESS_THRESHOLD || 0) || null;
  if (threshold && witnessUrls.length < threshold) {
    errors.push(`gateway WITNESS_THRESHOLD=${threshold} exceeds configured witness URL count ${witnessUrls.length}`);
  }
  if (threshold && alignment.email_registry_witness_key_ids.length < threshold) {
    errors.push(`email registry authorizes ${alignment.email_registry_witness_key_ids.length} active L1 witness key(s), below gateway threshold ${threshold}`);
  }
  if (gatewayConfig.REGISTRY_EPOCH_ID && gatewayConfig.REGISTRY_EPOCH_ID !== l1.epoch_id) {
    errors.push(`gateway REGISTRY_EPOCH_ID does not match L1 pointer: expected=${gatewayConfig.REGISTRY_EPOCH_ID} actual=${l1.epoch_id}`);
  }
  if (!gatewayConfig.REGISTRY_EPOCH_DIGEST) {
    warnings.push("gateway REGISTRY_EPOCH_DIGEST pin was not found in local gateway config");
  }
  return {
    config_file: existsSync(gatewayConfigPath) ? gatewayConfigPath : null,
    witness_urls: witnessUrls,
    witness_threshold: threshold,
    expected_l1_registry_epoch_id: gatewayConfig.REGISTRY_EPOCH_ID || null,
    expected_email_registry_epoch_digest: gatewayConfig.REGISTRY_EPOCH_DIGEST || null,
    email_registry_epoch_digest: email.epoch_digest,
    email_registry_pin_matched: email.digest_matches_gateway_pin,
    l1_registry_epoch_id: l1.epoch_id,
    l1_registry_epoch_matched: gatewayConfig.REGISTRY_EPOCH_ID ? gatewayConfig.REGISTRY_EPOCH_ID === l1.epoch_id : null
  };
}

function activeMechanicalWitnesses(epoch, { workflowId, policyHash }) {
  return (epoch?.witnesses || [])
    .filter((witness) => witness.tier === "mechanical")
    .filter((witness) => witness.status === "active")
    .filter((witness) => !workflowId || (witness.authorized_workflows || []).includes(workflowId))
    .filter((witness) => !policyHash || (witness.authorized_policy_hashes || []).includes(policyHash))
    .map((witness) => ({
      witness_id: witness.witness_id,
      key_id: witness.key_id,
      witness_epoch_id: witness.witness_epoch_id || null,
      valid_until: witness.valid_until || null
    }));
}

function registryTiming(pointer, { warningDays, criticalDays }) {
  const refreshAt = pointer.refresh_by ? Date.parse(pointer.refresh_by) : NaN;
  const expiresAt = pointer.valid_until ? Date.parse(pointer.valid_until) : NaN;
  const nowMs = now.getTime();
  return {
    warning_days: warningDays,
    critical_days: criticalDays,
    days_until_refresh: Number.isFinite(refreshAt) ? roundDays(refreshAt - nowMs) : null,
    days_until_expiry: Number.isFinite(expiresAt) ? roundDays(expiresAt - nowMs) : null,
    past_refresh_by: Number.isFinite(refreshAt) ? nowMs >= refreshAt : false,
    expired: Number.isFinite(expiresAt) ? nowMs >= expiresAt : false
  };
}

async function fetchJson(url) {
  const response = await fetch(url);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}: ${text}`);
  }
  return JSON.parse(text);
}

function parseTinfoilEnv(text) {
  const env = {};
  for (const line of text.split("\n")) {
    const match = line.match(/^\s*-\s*([A-Z0-9_]+):\s*(.*)$/);
    if (!match) {
      continue;
    }
    env[match[1]] = stripQuotes(match[2].trim());
  }
  if (env.REGISTRY_TRUST_ANCHOR_PUBLIC_KEY_PEM_BASE64 && !env.REGISTRY_TRUST_ANCHOR_PUBLIC_KEY_PEM) {
    env.REGISTRY_TRUST_ANCHOR_PUBLIC_KEY_PEM = Buffer.from(env.REGISTRY_TRUST_ANCHOR_PUBLIC_KEY_PEM_BASE64, "base64").toString("utf8");
  }
  return env;
}

function stripQuotes(value) {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}

function parseWitnessUrls(value) {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean).map((item) => {
    const equals = item.indexOf("=");
    return equals === -1
      ? { id: "", url: item }
      : { id: item.slice(0, equals), url: item.slice(equals + 1) };
  });
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--")) {
      continue;
    }
    const key = arg.slice(2);
    const next = argv[index + 1];
    parsed[key] = next && !next.startsWith("--") ? next : "true";
    if (next && !next.startsWith("--")) {
      index += 1;
    }
  }
  return parsed;
}

function numberArg(name, fallback) {
  const value = args[name] ?? process.env[`REGISTRY_POSTURE_${name.toUpperCase().replace(/-/g, "_")}`];
  return value === undefined ? fallback : Number(value);
}

function stripSlash(value) {
  return String(value || "").replace(/\/$/, "");
}

function roundDays(ms) {
  return Math.round((ms / (24 * 60 * 60_000)) * 100) / 100;
}

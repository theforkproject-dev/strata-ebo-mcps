import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

export function loadCertificateBundle({ config, runId, runDir, bundleUrl = "", durablePublication = null, recipientVerifications = [] }) {
  const certificate = readJson(join(runDir, "certificate.json"));
  return {
    version: "strata.email.certificate_bundle.v1",
    run_id: runId,
    bundle_url: bundleUrl || `${config.certificateBaseUrl}/${runId}/bundle`,
    gateway_bundle_url: `${config.certificateBaseUrl}/${runId}/bundle`,
    durable_publication: durablePublication,
    certificate,
    receipts: readJsonl(join(runDir, "receipts.jsonl")),
    keyring: readJson(join(runDir, "keyring.json")),
    checkpoint: readJson(join(runDir, "checkpoint.json")),
    transparency_log: readJsonl(join(runDir, "transparency-log.jsonl")),
    verification: readJson(join(runDir, "verification.json")),
    admission_manifest: readOptionalJson(join(runDir, "admission-manifest.json")),
    operator_registry: readOptionalJson(join(runDir, "operator-registry.json")),
    policy_decision: readOptionalJson(join(runDir, "policy-decision.json")),
    policy_bundle: readOptionalJson(join(runDir, "policy-bundle.json")),
    registry_epoch: readOptionalJson(join(runDir, "registry-epoch.json")),
    gateway_attestation: readOptionalJson(join(runDir, "gateway-attestation.json")),
    l1_witness_attestations: readOptionalJson(join(runDir, "l1-witness-attestations.json")),
    recipient_verifications: recipientVerifications
  };
}

export function loadRecipientVerifications({ config, certificate, runId }) {
  const dir = join(config.dataDir, "recipient-verifications");
  if (!existsSync(dir)) {
    return [];
  }
  return readdirSync(dir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => readOptionalJson(join(dir, file)))
    .filter(Boolean)
    .filter((receipt) => receipt.certificate_digest === certificate.certificate_digest || String(receipt.certificate_ref || "").includes(runId));
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function readOptionalJson(path) {
  if (!existsSync(path)) {
    return null;
  }
  return readJson(path);
}

function readJsonl(path) {
  if (!existsSync(path)) {
    return [];
  }
  return readFileSync(path, "utf8").split("\n").filter((line) => line.trim()).map((line) => JSON.parse(line));
}

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

export function loadCertificateBundle({ config, runId, runDir, bundleUrl = "", durablePublication = null, recipientVerifications = [] }) {
  const certificate = readJson(join(runDir, "certificate.json"));
  const isSupabase = String(certificate.version || "").startsWith("strata.supabase.");
  const isKojimem = String(certificate.version || "").startsWith("strata.kojimem.");
  return {
    version: isKojimem ? "strata.kojimem.certificate_bundle.v1" : isSupabase ? "strata.supabase.certificate_bundle.v1" : "strata.email.certificate_bundle.v1",
    run_id: runId,
    bundle_url: bundleUrl || `${config.certificateBaseUrl}/${runId}/bundle`,
    gateway_bundle_url: `${config.certificateBaseUrl}/${runId}/bundle`,
    durable_publication: durablePublication,
    certificate,
    receipts: readJsonl(join(runDir, "receipts.jsonl")),
    keyring: readOptionalJson(join(runDir, "keyring.json")),
    checkpoint: readOptionalJson(join(runDir, "checkpoint.json")),
    transparency_log: readJsonl(join(runDir, "transparency-log.jsonl")),
    verification: readOptionalJson(join(runDir, "verification.json")),
    admission_manifest: readOptionalJson(join(runDir, "admission-manifest.json")),
    operator_registry: readOptionalJson(join(runDir, "operator-registry.json")),
    policy_decision: readOptionalJson(join(runDir, "policy-decision.json")),
    policy_bundle: readOptionalJson(join(runDir, "policy-bundle.json")),
    registry_epoch: readOptionalJson(join(runDir, "registry-epoch.json")),
    gateway_attestation: readOptionalJson(join(runDir, "gateway-attestation.json")),
    l1_witness_attestations: readOptionalJson(join(runDir, "l1-witness-attestations.json")),
    connector_manifest: readOptionalJson(join(runDir, "connector-manifest.json")),
    supabase_request: readOptionalJson(join(runDir, "supabase-request.json")),
    supabase_result_metadata: readOptionalJson(join(runDir, "supabase-result-metadata.json")),
    kojimem_request: readOptionalJson(join(runDir, "kojimem-request.json")),
    kojimem_result_metadata: readOptionalJson(join(runDir, "kojimem-result-metadata.json")),
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

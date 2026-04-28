#!/usr/bin/env node
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  certificateBundleDigest,
  collectWitnessedSubjects,
  createDomainAttestation,
  signDomainAttestation,
  signWitnessRegistryEpoch,
  verifyDomainAttestation,
  verifyWitnessAuthority
} from "../src/index.js";

const args = parseArgs(process.argv.slice(2));
const certificateDir = args.certificate ?? latestHostedDemoDir();
const workflowId = args.workflow ?? "turnstile-demo.payment";
const requiredTier = args["required-tier"] ?? "mechanical";
const registryPath = args.registry ?? join(certificateDir, "registry-epoch.json");
const registryTrustPath = args["registry-trust"] ?? join(certificateDir, "registry-trust-anchor.json");
const domainAttestationPath = args["domain-attestation"] ?? join(certificateDir, "domain-attestation.json");
const domainTrustPath = args["domain-trust"] ?? join(certificateDir, "domain-trust-anchor.json");
const refresh = truthy(args.refresh);

const certificate = loadCertificate(certificateDir);
if (!certificate.verification?.ok) {
  throw new Error(`${certificateDir}/verification.json is missing or not ok; run npm run demo:hosted first`);
}

if (refresh || !existsSync(registryPath) || !existsSync(registryTrustPath)) {
  generateRegistryExample({ certificate, workflowId, registryPath, registryTrustPath });
}

const registryEpoch = readJson(registryPath);
const registryTrust = readJson(registryTrustPath);
const policyHash = certificate.receipts[0]?.body?.policy_hash;
if (!policyHash) {
  throw new Error("certificate session.start receipt does not contain a policy hash");
}

const registry = verifyWitnessAuthority({
  receipts: certificate.receipts,
  checkpoint: certificate.checkpoint,
  keyring: certificate.keyring,
  registryEpoch,
  trustAnchors: registryTrust,
  workflowId,
  policyHash,
  requiredTier
});

const certificateDigest = certificateBundleDigest(certificate);
if (refresh || !existsSync(domainAttestationPath) || !existsSync(domainTrustPath)) {
  generateDomainAttestationExample({
    certificateDigest,
    registryEpoch,
    domainAttestationPath,
    domainTrustPath
  });
}

const domainAttestation = readJson(domainAttestationPath);
const domainTrust = readJson(domainTrustPath);
const domain = verifyDomainAttestation(domainAttestation, {
  certificateDigest,
  attestorKeyring: domainTrust.keyring ?? domainTrust
});

const summary = {
  ok: registry.ok && domain.ok,
  certificate_dir: certificateDir,
  certificate_digest: certificateDigest,
  workflow_id: workflowId,
  policy_hash: policyHash,
  required_tier: requiredTier,
  registry: {
    ok: registry.ok,
    epoch_id: registryEpoch.epoch_id,
    registry_epoch_digest: registry.registry_epoch_digest,
    checks: registry.checks.map((check) => ({
      label: check.label,
      ok: check.ok,
      signing_time: check.signing_time,
      quorum_threshold: check.quorum_threshold,
      authorized_witness_keys: check.authorized_witness_keys
    })),
    errors: registry.errors,
    warnings: registry.warnings
  },
  domain_attestation: {
    ok: domain.ok,
    attestation_id: domainAttestation.attestation_id,
    attestor_id: domainAttestation.attestor_id,
    domain: domainAttestation.domain,
    claim: domainAttestation.claim,
    attestation_digest: domain.attestation_digest,
    errors: domain.errors
  }
};

writeJson(join(certificateDir, "registry-demo-summary.json"), summary);
console.log(JSON.stringify(summary, null, 2));
process.exitCode = summary.ok ? 0 : 1;

function generateRegistryExample({ certificate, workflowId, registryPath, registryTrustPath }) {
  mkdirSync(dirname(registryPath), { recursive: true });
  const keys = generateKeyPairSync("ed25519");
  const signer = {
    keyId: "registry-authority:amotivv-demo:v1",
    privateKey: keys.privateKey
  };
  const publicKeyPem = keys.publicKey.export({ type: "spki", format: "pem" });
  const policyHash = certificate.receipts[0]?.body?.policy_hash;
  const issuedAt = certificate.receipts[0]?.issued_at ?? new Date().toISOString();
  const validFrom = offsetIso(issuedAt, -60 * 1000);
  const validUntil = offsetIso(issuedAt, 10 * 365 * 24 * 60 * 60 * 1000);
  const witnessIds = witnessIdsByKey(certificate);
  const witnesses = Object.entries(certificate.keyring)
    .filter(([keyId]) => keyId.startsWith("witness:"))
    .map(([keyId, public_key_pem]) => ({
      witness_id: witnessIds[keyId] ?? keyId.split(":")[1] ?? keyId,
      key_id: keyId,
      public_key_pem,
      operator: `demo ${witnessIds[keyId] ?? keyId}`,
      tier: "mechanical",
      authorized_workflows: [workflowId],
      authorized_policy_hashes: [policyHash],
      valid_from: validFrom,
      valid_until: validUntil,
      status: "active",
      status_events: [
        { status: "active", effective_at: validFrom, reason: "demo epoch activation" },
        { status: "deprecated", effective_at: validUntil, reason: "demo epoch expiry; valid prior certificates remain verifiable" }
      ]
    }));

  const epoch = signWitnessRegistryEpoch({
    version: "turnstile.witness-registry-epoch.v1",
    registry_id: "registry.amotivv.demo",
    epoch_id: `demo-epoch-${Date.now()}`,
    governance_layer: "witness-registry",
    valid_from: validFrom,
    valid_until: validUntil,
    published_at: new Date().toISOString(),
    workflow_scopes: [workflowId],
    policy_hashes: [policyHash],
    verifier_profile_hashes: [certificate.receipts[0]?.body?.verifier_profile_hash].filter(Boolean),
    witness_thresholds: { mechanical: 2 },
    status_semantics: {
      deprecated: "valid for certificates signed before deprecation; not authorized for new signing after effective_at",
      revoked: "invalid for signatures at or after effective_at unless a later registry epoch narrows the revocation",
      compromised: "invalid for signatures at or after invalidates_from/compromise_from"
    },
    witnesses
  }, signer);

  writeJson(registryPath, epoch);
  writeJson(registryTrustPath, {
    registry_id: epoch.registry_id,
    keyring: { [signer.keyId]: publicKeyPem }
  });
}

function generateDomainAttestationExample({ certificateDigest, registryEpoch, domainAttestationPath, domainTrustPath }) {
  mkdirSync(dirname(domainAttestationPath), { recursive: true });
  const keys = generateKeyPairSync("ed25519");
  const signer = {
    keyId: "domain-attestor:financial-controls-demo:v1",
    privateKey: keys.privateKey
  };
  const publicKeyPem = keys.publicKey.export({ type: "spki", format: "pem" });
  const attestation = signDomainAttestation(createDomainAttestation({
    attestationId: `domain-attestation-${Date.now()}`,
    attestorId: "financial-controls-demo",
    domain: "financial-controls",
    certificateDigest,
    registryEpochId: registryEpoch.epoch_id,
    claim: "Demo domain attestor reviewed the procedurally valid TURNSTILE certificate for payment-control conformance shape.",
    evidenceRefs: ["demo://no-external-review-performed"]
  }), signer);

  writeJson(domainAttestationPath, attestation);
  writeJson(domainTrustPath, {
    attestor_id: attestation.attestor_id,
    keyring: { [signer.keyId]: publicKeyPem }
  });
}

function loadCertificate(dir) {
  return {
    receipts: readJsonl(join(dir, "receipts.jsonl")),
    checkpoint: readJson(join(dir, "checkpoint.json")),
    keyring: readJson(join(dir, "keyring.json")),
    transparencyLogEntries: readJsonl(join(dir, "transparency-log.jsonl")),
    verification: existsSync(join(dir, "verification.json")) ? readJson(join(dir, "verification.json")) : null
  };
}

function witnessIdsByKey(certificate) {
  const ids = {};
  for (const item of collectWitnessedSubjects({ receipts: certificate.receipts, checkpoint: certificate.checkpoint })) {
    for (const signature of item.certificate.signatures ?? []) {
      ids[signature.key_id] = signature.witness_id;
    }
  }
  return ids;
}

function latestHostedDemoDir() {
  const root = join("artifacts", "hosted-demo");
  if (!existsSync(root)) {
    throw new Error("No hosted demo artifacts found. Run `npm run demo:hosted` first.");
  }
  const dirs = readdirSync(root)
    .map((name) => join(root, name))
    .filter((path) => statSync(path).isDirectory() && existsSync(join(path, "summary.json")))
    .sort();
  const latest = dirs.at(-1);
  if (!latest) {
    throw new Error("No hosted demo artifact directory with summary.json found. Run `npm run demo:hosted` first.");
  }
  return latest;
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function readJsonl(filePath) {
  return readFileSync(filePath, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse);
}

function writeJson(filePath, value) {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function offsetIso(value, offsetMs) {
  return new Date(new Date(value).getTime() + offsetMs).toISOString();
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

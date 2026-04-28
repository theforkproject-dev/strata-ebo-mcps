#!/usr/bin/env node
import { createServer } from "node:http";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  ActionGateway,
  HttpWitnessClient,
  JsonlReceiptLog,
  LocalTransparencyLog,
  Witness,
  createAdmissionManifest,
  createPaymentsTool,
  createTinfoilEvidence,
  createVerifierProfile,
  loadOrCreateEd25519Signer,
  sha256Hex,
  writeCheckpoint
} from "../src/index.js";

const args = parseArgs(process.argv.slice(2));
const port = Number(args.port ?? process.env.PORT ?? 8787);
const host = args.host ?? process.env.HOST ?? "127.0.0.1";
const dataDir = args["data-dir"] ?? process.env.TURNSTILE_DATA_DIR ?? join("artifacts", "gateway");
const logPath = args.log ?? process.env.TURNSTILE_LOG ?? join(dataDir, "receipts.jsonl");
const keyringPath = args.keyring ?? join(dirname(logPath), "keyring.json");
const transparencyLogPath = args["transparency-log"] ?? join(dirname(logPath), "transparency-log.jsonl");
const checkpointPath = args.checkpoint ?? join(dirname(logPath), "checkpoint.json");
const demoResetEnabled = truthy(args["demo-reset-enabled"] ?? process.env.DEMO_RESET_ENABLED);

mkdirSync(dirname(logPath), { recursive: true });

const gatewayKey = loadSigner({
  prefix: "GATEWAY",
  keyFile: args["gateway-key-file"] ?? process.env.GATEWAY_KEY_FILE ?? join(dataDir, "gateway.key.json"),
  keyId: args["gateway-key-id"] ?? process.env.GATEWAY_KEY_ID ?? "gateway:local:http"
});
const toolKey = loadSigner({
  prefix: "TOOL",
  keyFile: args["tool-key-file"] ?? process.env.TOOL_KEY_FILE ?? join(dataDir, "tool.key.json"),
  keyId: args["tool-key-id"] ?? process.env.TOOL_KEY_ID ?? "tool:payments-api:http"
});
const transparencyKey = loadSigner({
  prefix: "TRANSPARENCY",
  keyFile: args["transparency-key-file"] ?? process.env.TRANSPARENCY_KEY_FILE ?? join(dataDir, "transparency.key.json"),
  keyId: args["transparency-key-id"] ?? process.env.TRANSPARENCY_KEY_ID ?? "transparency:local:http"
});
const gatewaySigner = gatewayKey.signer;
const toolSigner = toolKey.signer;
const transparencySigner = transparencyKey.signer;
const keyring = {
  [gatewaySigner.keyId]: gatewayKey.publicKeyPem,
  [toolSigner.keyId]: toolKey.publicKeyPem,
  [transparencySigner.keyId]: transparencyKey.publicKeyPem
};
const witnessSpecs = parseWitnessSpecs(args["witness-urls"] ?? process.env.WITNESS_URLS ?? "");
const { witnesses, witnessPublicKeys } = witnessSpecs.length > 0
  ? await createHttpWitnesses(witnessSpecs)
  : createLocalWitnesses({ dataDir, keyring });
for (const publicKey of witnessPublicKeys) {
  keyring[publicKey.key_id] = publicKey.public_key_pem;
}
writeFileSync(keyringPath, `${JSON.stringify(keyring, null, 2)}\n`, "utf8");

const log = new JsonlReceiptLog(logPath);
const transparencyLog = new LocalTransparencyLog({
  filePath: transparencyLogPath,
  signer: transparencySigner,
  logId: "local-http-transparency-log"
});
const egressPolicy = createEgressPolicy({ witnessSpecs });
const policyHash = sha256Hex(args["policy-hash"] ?? process.env.POLICY_HASH ?? JSON.stringify(egressPolicy));
const verifierProfile = createVerifierProfile({ profile_id: "profile.http-gateway.v1" });
const admissionManifest = createAdmissionManifest({
  manifestId: "adm_http_gateway_v1",
  governanceId: "gov_http_gateway_v1",
  policyHash,
  agent: tinfoilEvidence("agent", [], null),
  gateway: tinfoilEvidence("gateway", ["/v1/*"], egressPolicy),
  verifier: tinfoilEvidence("verifier", ["/verify"], null),
  approvedTools: [{ tool_id: "payments-api", audience: "payments-api", methods: ["POST /v1/payments"] }],
  approvedDataSources: ["mock-db"],
  approvedModels: ["mock.local"],
  witnessSetId: process.env.WITNESS_SET_ID ?? "witness-set.http-gateway",
  witnessThreshold: 2
});
let gateway = createGateway();

const server = createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/health") {
      return json(response, 200, { ok: true, witness_mode: witnessSpecs.length > 0 ? "http" : "local" });
    }

    if (request.method === "GET" && request.url === "/v1/public-key") {
      return json(response, 200, {
        key_id: gatewaySigner.keyId,
        public_key_pem: gatewayKey.publicKeyPem
      });
    }

    if (request.method === "GET" && request.url === "/v1/keyring") {
      return json(response, 200, { keyring });
    }

    if (request.method === "GET" && request.url === "/v1/admission-manifest") {
      return json(response, 200, { admission_manifest: admissionManifest });
    }

    if (request.method === "GET" && request.url === "/v1/verifier-profile") {
      return json(response, 200, { verifier_profile: verifierProfile });
    }

    if (request.method === "GET" && request.url === "/v1/egress-policy") {
      return json(response, 200, { egress_policy: egressPolicy });
    }

    if (request.method === "POST" && request.url === "/v1/demo/reset") {
      if (!demoResetEnabled) {
        return json(response, 403, { error: "demo reset is disabled" });
      }
      log.reset();
      transparencyLog.reset();
      rmSync(checkpointPath, { force: true });
      gateway = createGateway();
      return json(response, 200, { ok: true, reset: true, witness_mode: witnessSpecs.length > 0 ? "http" : "local" });
    }

    if (request.method === "GET" && request.url === "/v1/receipts") {
      return json(response, 200, { receipts: log.readAll() });
    }

    if (request.method === "GET" && request.url === "/v1/transparency-log") {
      return json(response, 200, { entries: transparencyLog.readAll() });
    }

    if (request.method === "POST" && request.url === "/v1/sessions") {
      const body = await readJson(request);
      const receipt = await gateway.startSession(body);
      return json(response, 201, { receipt, keyring_path: keyringPath, log_path: logPath });
    }

    if (request.method === "POST" && request.url === "/v1/sessions/end") {
      const body = await readJson(request);
      const receipt = await gateway.endSession(body.reason ?? "complete");
      return json(response, 201, { receipt });
    }

    if (request.method === "POST" && request.url === "/v1/actions") {
      const body = await readJson(request);
      const result = await dispatchAction(gateway, body);
      return json(response, 200, result);
    }

    if (request.method === "POST" && request.url === "/v1/checkpoints") {
      const checkpoint = await gateway.createCheckpoint();
      writeCheckpoint(checkpointPath, checkpoint);
      return json(response, 201, { checkpoint, checkpoint_path: checkpointPath });
    }

    json(response, 404, { error: "not found" });
  } catch (error) {
    json(response, 400, { error: error.message });
  }
});

server.listen(port, host, () => {
  console.log(JSON.stringify({
    ok: true,
    url: `http://${host === "0.0.0.0" ? "127.0.0.1" : host}:${port}`,
    port,
    host,
    witness_mode: witnessSpecs.length > 0 ? "http" : "local",
    witness_urls: witnessSpecs.map((witness) => `${witness.id}=${witness.url}`),
    gateway_key_id: gatewaySigner.keyId,
    demo_reset_enabled: demoResetEnabled,
    log_path: logPath,
    keyring_path: keyringPath,
    checkpoint_path: checkpointPath,
    transparency_log_path: transparencyLogPath,
    egress_policy: egressPolicy
  }, null, 2));
});

function createGateway() {
  const tool = createPaymentsTool({ signer: toolSigner, gatewayKeyring: keyring });
  return new ActionGateway({
    log,
    signer: gatewaySigner,
    tools: { [tool.name]: tool },
    policyHash,
    verifierProfile,
    admissionManifest,
    witnesses,
    sideEffectWitnessThreshold: 2,
    sessionBoundaryWitnessThreshold: 2,
    transparencyLog
  });
}

async function dispatchAction(gateway, body) {
  switch (body.type) {
    case "model.call":
      return gateway.modelCall(body);
    case "model.abort":
      return gateway.abortModelCall(body);
    case "data.query":
      return gateway.dataQuery(body);
    case "human.approval":
      return gateway.humanApproval(body);
    case "tool.call":
      return gateway.toolCall(body);
    case "tool.abort":
      return gateway.abortToolCall(body);
    default:
      throw new Error(`Unknown action type: ${body.type}`);
  }
}

async function readJson(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw.length === 0 ? {} : JSON.parse(raw);
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) {
      continue;
    }
    parsed[item.slice(2)] = argv[index + 1];
    index += 1;
  }
  return parsed;
}

function truthy(value) {
  return value === true || value === "true" || value === "1" || value === "yes";
}

function tinfoilEvidence(containerName, shimPaths, egressPolicy) {
  const prefix = containerName.toUpperCase().replace(/[^A-Z0-9]/g, "_");
  return createTinfoilEvidence({
    containerName,
    imageDigest: process.env[`${prefix}_IMAGE_DIGEST`] ?? `sha256:${sha256Hex(`http:${containerName}`)}`,
    configHash: process.env[`${prefix}_TINFOIL_CONFIG_HASH`] ?? sha256Hex(process.env[`${prefix}_TINFOIL_CONFIG_REF`] ?? `config:${containerName}`),
    attestationRef: process.env[`${prefix}_ATTESTATION_REF`] ?? `https://${containerName}.local/.well-known/tinfoil-attestation`,
    sigstoreBundleRef: process.env[`${prefix}_SIGSTORE_BUNDLE_REF`] ?? `sigstore://http/${containerName}`,
    shimPaths,
    egressPolicy
  });
}

function loadSigner({ prefix, keyFile, keyId }) {
  return loadOrCreateEd25519Signer({
    keyFile,
    keyId,
    keyJson: process.env[`${prefix}_KEY_JSON`],
    privateKeyPem: process.env[`${prefix}_PRIVATE_KEY_PEM`],
    publicKeyPem: process.env[`${prefix}_PUBLIC_KEY_PEM`]
  });
}

function createLocalWitnesses({ dataDir, keyring }) {
  const witnesses = [];
  const witnessPublicKeys = [];
  for (let index = 1; index <= 3; index += 1) {
    const id = `w${index}`;
    const { signer, publicKeyPem } = loadOrCreateEd25519Signer({
      keyFile: join(dataDir, `witness-${index}.key.json`),
      keyId: `witness:${id}:http`
    });
    keyring[signer.keyId] = publicKeyPem;
    witnessPublicKeys.push({ key_id: signer.keyId, public_key_pem: publicKeyPem });
    witnesses.push(new Witness({
      id,
      signer,
      walPath: join(dataDir, `witness-${index}.jsonl`)
    }));
  }
  return { witnesses, witnessPublicKeys };
}

async function createHttpWitnesses(witnessSpecs) {
  const witnesses = witnessSpecs.map((spec) => new HttpWitnessClient(spec));
  const witnessPublicKeys = [];
  for (const witness of witnesses) {
    witnessPublicKeys.push(await witness.publicKey());
  }
  return { witnesses, witnessPublicKeys };
}

function parseWitnessSpecs(value) {
  return value.split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item, index) => {
      const equals = item.indexOf("=");
      if (equals === -1) {
        return { id: `w${index + 1}`, url: item };
      }
      return { id: item.slice(0, equals), url: item.slice(equals + 1) };
    });
}

function createEgressPolicy({ witnessSpecs }) {
  const mode = process.env.EGRESS_POLICY_MODE ?? (witnessSpecs.length > 0 ? "witness-urls-only" : "typed-adapters-only");
  return {
    mode,
    allowed_urls: witnessSpecs.map((witness) => witness.url),
    evidence_ref: process.env.EGRESS_POLICY_REF ?? "tinfoil-config.yml:containers[0].env",
    enforcement: process.env.EGRESS_POLICY_ENFORCEMENT ?? "application-code-typed-adapters",
    notes: [
      "The Tinfoil config commits this policy as measured environment variables.",
      "This is application-level egress discipline unless paired with a Tinfoil/native network control."
    ]
  };
}

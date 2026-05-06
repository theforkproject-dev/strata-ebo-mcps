import { existsSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";

export function loadConfig(env = process.env) {
  loadDotEnv(env);

  const sessionSecret = env.MCP_SESSION_SECRET || randomBytes(32).toString("hex");
  const dataDir = env.DATA_DIR || "artifacts/email-mcp";
  const publicBaseUrl = trimSlash(env.PUBLIC_BASE_URL || `http://${env.HOST || "127.0.0.1"}:${env.PORT || "8899"}`);
  const registryUrl = trimSlash(env.REGISTRY_URL || "");
  const registryTrustAnchorPublicKeyPem = env.REGISTRY_TRUST_ANCHOR_PUBLIC_KEY_PEM
    || (env.REGISTRY_TRUST_ANCHOR_PUBLIC_KEY_PEM_BASE64 ? Buffer.from(env.REGISTRY_TRUST_ANCHOR_PUBLIC_KEY_PEM_BASE64, "base64").toString("utf8") : "");
  const policyBundleEpochId = env.POLICY_BUNDLE_EPOCH_ID || "email-policy-epoch-001";
  const operatorAdmissionPublicKeyPem = env.OPERATOR_ADMISSION_PUBLIC_KEY_PEM
    || (env.OPERATOR_ADMISSION_PUBLIC_KEY_PEM_BASE64 ? Buffer.from(env.OPERATOR_ADMISSION_PUBLIC_KEY_PEM_BASE64, "base64").toString("utf8") : "");
  const gatewayKeyBundle = readOptionalJson(env.GATEWAY_KEY_BUNDLE_FILE || env.TINFOIL_WITNESS_POC_GATEWAY_KEY_FILE || "");
  const bundledGateway = gatewayKeyBundle?.gateway ?? null;

  return {
    host: env.HOST || "127.0.0.1",
    port: Number(env.PORT || 8899),
    sessionSecret,
    sessionSecretWasGenerated: !env.MCP_SESSION_SECRET,
    bearerToken: env.MCP_BEARER_TOKEN || "",
    allowedOrigins: parseCsv(env.MCP_ALLOWED_ORIGINS || ""),
    dataDir,
    publicBaseUrl,
    certificateBaseUrl: trimSlash(env.CERTIFICATE_BASE_URL || `${publicBaseUrl}/certificates`),
    email: {
      provider: env.EMAIL_PROVIDER || "resend",
      from: env.EMAIL_FROM || "",
      resendApiKey: env.RESEND_API_KEY || "",
      resendBaseUrl: trimSlash(env.RESEND_BASE_URL || "https://api.resend.com")
    },
    certificateBundle: {
      backend: env.CERTIFICATE_BUNDLE_STORE_BACKEND || "local",
      awsRegion: env.CERTIFICATE_BUNDLE_AWS_REGION || env.AWS_REGION || "",
      awsAccessKeyId: env.CERTIFICATE_BUNDLE_AWS_ACCESS_KEY_ID || "",
      awsSecretAccessKey: env.CERTIFICATE_BUNDLE_AWS_SECRET_ACCESS_KEY || "",
      s3Bucket: env.CERTIFICATE_BUNDLE_S3_BUCKET || "",
      s3Prefix: trimSlash(env.CERTIFICATE_BUNDLE_S3_PREFIX || "certificates"),
      publicBaseUrl: trimSlash(env.CERTIFICATE_BUNDLE_PUBLIC_BASE || ""),
      lockMode: env.CERTIFICATE_BUNDLE_LOCK_MODE || "",
      publishRequired: truthy(env.CERTIFICATE_BUNDLE_PUBLISH_REQUIRED)
    },
    oauth: {
      enabled: Boolean(env.OAUTH_ISSUER),
      issuer: trimSlash(env.OAUTH_ISSUER || publicBaseUrl),
      storePath: env.OAUTH_STORE_PATH || `${dataDir}/oauth-store.json`,
      consentPassword: env.OAUTH_CONSENT_PASSWORD || "",
      consentPasswordHash: env.OAUTH_CONSENT_PASSWORD_SHA256 || "",
      accessTokenTtlMs: Number(env.OAUTH_ACCESS_TOKEN_TTL_SECONDS || 3600) * 1000,
      refreshTokenTtlMs: Number(env.OAUTH_REFRESH_TOKEN_TTL_SECONDS || 30 * 24 * 3600) * 1000,
      codeTtlMs: Number(env.OAUTH_CODE_TTL_SECONDS || 600) * 1000
    },
    registry: {
      url: registryUrl,
      expectedEpochDigest: env.REGISTRY_EPOCH_DIGEST || "",
      trustAnchorKeyId: env.REGISTRY_TRUST_ANCHOR_KEY_ID || "",
      trustAnchorPublicKeyPem: registryTrustAnchorPublicKeyPem
    },
    policy: {
      bundleFile: env.POLICY_BUNDLE_FILE || "policies/email-policy-epoch-001.json",
      bundleUrl: trimSlash(env.POLICY_BUNDLE_URL || (registryUrl ? `${registryUrl}/policies/epochs/${policyBundleEpochId}` : "")),
      epochId: policyBundleEpochId,
      expectedDigest: env.POLICY_BUNDLE_DIGEST || ""
    },
    tenant: {
      id: env.TENANT_ID || "default"
    },
    gateway: {
      id: env.GATEWAY_ID || bundledGateway?.gateway_id || "gateway:email-mcp",
      keyId: env.GATEWAY_KEY_ID || bundledGateway?.key_id || "gateway:email-mcp",
      keyFile: env.GATEWAY_KEY_FILE || `${dataDir}/keys/gateway.key.json`,
      keyJson: env.GATEWAY_KEY_JSON || "",
      privateKeyPem: env.GATEWAY_PRIVATE_KEY_PEM || bundledGateway?.private_key_pem || "",
      publicKeyPem: env.GATEWAY_PUBLIC_KEY_PEM || bundledGateway?.public_key_pem || "",
      keyBundleFile: env.GATEWAY_KEY_BUNDLE_FILE || env.TINFOIL_WITNESS_POC_GATEWAY_KEY_FILE || ""
    },
    operator: {
      id: env.OPERATOR_ID || "operator:amotivv-demo",
      admissionKeyId: env.OPERATOR_ADMISSION_KEY_ID || "operator-admission:amotivv-demo",
      admissionKeyFile: env.OPERATOR_ADMISSION_KEY_FILE || `${dataDir}/keys/operator-admission.key.json`,
      admissionKeyJson: env.OPERATOR_ADMISSION_KEY_JSON || "",
      admissionPrivateKeyPem: env.OPERATOR_ADMISSION_PRIVATE_KEY_PEM || "",
      admissionPublicKeyPem: operatorAdmissionPublicKeyPem
    },
    witnesses: parseWitnessUrls(env.WITNESS_URLS || "", "w"),
    witness: {
      threshold: positiveInt(env.WITNESS_THRESHOLD || env.L1_WITNESS_THRESHOLD || 2, "WITNESS_THRESHOLD"),
      signedRequests: {
        enabled: truthy(env.GATEWAY_SIGNED_WITNESS_REQUESTS_ENABLED || env.WITNESS_SIGN_REQUESTS_ENABLED),
        witnessEpochId: env.WITNESS_EPOCH_ID || "",
        registryEpochId: env.REGISTRY_EPOCH_ID || "",
        workflowId: env.WITNESS_WORKFLOW_ID || "email.send"
      }
    },
    policyWitnesses: parseWitnessUrls(env.POLICY_WITNESS_URLS || "", "p"),
    policyWitness: {
      threshold: positiveInt(env.POLICY_WITNESS_THRESHOLD || env.L2_POLICY_WITNESS_THRESHOLD || 2, "POLICY_WITNESS_THRESHOLD")
    },
    attestation: {
      gateway: {
        containerName: env.GATEWAY_TINFOIL_CONTAINER_NAME || "",
        configRepo: env.GATEWAY_TINFOIL_CONFIG_REPO || "",
        configTag: env.GATEWAY_TINFOIL_CONFIG_TAG || "",
        imageDigest: normalizeImageDigest(env.GATEWAY_TINFOIL_IMAGE_DIGEST || ""),
        attestationDigest: env.GATEWAY_TINFOIL_ATTESTATION_DIGEST || "",
        attestationUrl: env.GATEWAY_TINFOIL_ATTESTATION_URL || "",
        attestationRequired: truthy(env.GATEWAY_TINFOIL_ATTESTATION_REQUIRED),
        attestationRef: env.GATEWAY_TINFOIL_ATTESTATION_REF || "",
        sigstoreBundleRef: env.GATEWAY_TINFOIL_SIGSTORE_BUNDLE_REF || ""
      },
      l1Witnesses: parseL1TinfoilEvidence(env)
    }
  };
}

export function parseWitnessUrls(value, prefix = "w") {
  return parseCsv(value).map((item, index) => {
    const eq = item.indexOf("=");
    if (eq === -1) {
      return { id: `${prefix}${index + 1}`, url: item };
    }
    return { id: item.slice(0, eq).trim(), url: item.slice(eq + 1).trim() };
  }).filter((item) => item.id && item.url);
}

function parseCsv(value) {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function trimSlash(value) {
  return String(value).replace(/\/$/, "");
}

function truthy(value) {
  return ["1", "true", "yes", "on"].includes(String(value || "").toLowerCase());
}

function normalizeImageDigest(value) {
  if (!value) {
    return "";
  }
  return value.startsWith("sha256:") ? value : `sha256:${value}`;
}

function parseL1TinfoilEvidence(env) {
  if (env.L1_TINFOIL_EVIDENCE_JSON) {
    const parsed = JSON.parse(env.L1_TINFOIL_EVIDENCE_JSON);
    return (Array.isArray(parsed) ? parsed : [parsed]).map(normalizeL1Evidence).filter((item) => item.witnessId);
  }
  const item = normalizeL1Evidence({
    witnessId: env.L1_TINFOIL_WITNESS_ID || "",
    containerName: env.L1_TINFOIL_CONTAINER_NAME || "",
    configRepo: env.L1_TINFOIL_CONFIG_REPO || "",
    configTag: env.L1_TINFOIL_CONFIG_TAG || "",
    imageDigest: env.L1_TINFOIL_IMAGE_DIGEST || "",
    attestationDigest: env.L1_TINFOIL_ATTESTATION_DIGEST || "",
    attestationUrl: env.L1_TINFOIL_ATTESTATION_URL || "",
    attestationRequired: truthy(env.L1_TINFOIL_ATTESTATION_REQUIRED),
    attestationRef: env.L1_TINFOIL_ATTESTATION_REF || "",
    sigstoreBundleRef: env.L1_TINFOIL_SIGSTORE_BUNDLE_REF || ""
  });
  return item.witnessId ? [item] : [];
}

function normalizeL1Evidence(item) {
  return {
    witnessId: item.witnessId || item.witness_id || "",
    containerName: item.containerName || item.container_name || "",
    configRepo: item.configRepo || item.config_repo || "",
    configTag: item.configTag || item.config_tag || "",
    imageDigest: normalizeImageDigest(item.imageDigest || item.image_digest || ""),
    attestationDigest: item.attestationDigest || item.attestation_digest || "",
    attestationUrl: item.attestationUrl || item.attestation_url || "",
    attestationRequired: Boolean(item.attestationRequired || item.attestation_required),
    attestationRef: item.attestationRef || item.attestation_ref || "",
    sigstoreBundleRef: item.sigstoreBundleRef || item.sigstore_bundle_ref || ""
  };
}

function positiveInt(value, label) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
}

function readOptionalJson(path) {
  if (!path || !existsSync(path)) {
    return null;
  }
  return JSON.parse(readFileSync(path, "utf8"));
}

function loadDotEnv(env) {
  if (!existsSync(".env")) {
    return;
  }

  const raw = readFileSync(".env", "utf8");
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq === -1) {
      continue;
    }
    const key = trimmed.slice(0, eq).trim();
    if (env[key]) {
      continue;
    }
    env[key] = unquote(trimmed.slice(eq + 1).trim());
  }
}

function unquote(value) {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}

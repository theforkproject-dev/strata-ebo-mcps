import { existsSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { createKojimemAccount } from "./kojimem/client.js";

export function loadConfig(env = process.env) {
  loadDotEnv(env);

  const gatewayKind = String(env.STRATA_GATEWAY_KIND || env.GATEWAY_KIND || env.MCP_GATEWAY_KIND || "email").toLowerCase();
  const sessionSecret = env.MCP_SESSION_SECRET || randomBytes(32).toString("hex");
  const dataDir = env.DATA_DIR || (gatewayKind === "research" ? "artifacts/research-mcp" : gatewayKind === "managed-agent-policy" ? "artifacts/managed-agent-policy-gateway" : gatewayKind === "kojimem" ? "artifacts/kojimem-agent-handoff" : gatewayKind === "nango-supabase" ? "artifacts/nango-supabase-mcp" : gatewayKind === "supabase" ? "artifacts/supabase-mcp" : gatewayKind === "sharepoint" ? "artifacts/sharepoint-mcp" : gatewayKind === "gmail" ? "artifacts/gmail-mcp" : "artifacts/email-mcp");
  const publicBaseUrl = trimSlash(env.PUBLIC_BASE_URL || `http://${env.HOST || "127.0.0.1"}:${env.PORT || "8899"}`);
  const registryUrl = trimSlash(env.REGISTRY_URL || "");
  const registryTrustAnchorPublicKeyPem = env.REGISTRY_TRUST_ANCHOR_PUBLIC_KEY_PEM
    || (env.REGISTRY_TRUST_ANCHOR_PUBLIC_KEY_PEM_BASE64 ? Buffer.from(env.REGISTRY_TRUST_ANCHOR_PUBLIC_KEY_PEM_BASE64, "base64").toString("utf8") : "");
  const policyBundleEpochId = env.POLICY_BUNDLE_EPOCH_ID || "email-policy-epoch-001";
  const oauthStoreBackend = String(env.OAUTH_STORE_BACKEND || (env.OAUTH_DYNAMODB_TABLE || env.OAUTH_DYNAMODB_TABLE_NAME ? "dynamodb" : "file")).toLowerCase();
  const connectorCredentialStoreBackend = String(env.CONNECTOR_CREDENTIAL_STORE_BACKEND || env.SUPABASE_CONNECTOR_STORE_BACKEND || (env.CONNECTOR_CREDENTIAL_DYNAMODB_TABLE || env.SUPABASE_CONNECTOR_DYNAMODB_TABLE || env.OAUTH_DYNAMODB_TABLE || env.OAUTH_DYNAMODB_TABLE_NAME ? "dynamodb" : "file")).toLowerCase();
  const operatorAdmissionPublicKeyPem = env.OPERATOR_ADMISSION_PUBLIC_KEY_PEM
    || (env.OPERATOR_ADMISSION_PUBLIC_KEY_PEM_BASE64 ? Buffer.from(env.OPERATOR_ADMISSION_PUBLIC_KEY_PEM_BASE64, "base64").toString("utf8") : "");
  const gatewayKeyBundle = readOptionalJson(env.GATEWAY_KEY_BUNDLE_FILE || env.TINFOIL_WITNESS_POC_GATEWAY_KEY_FILE || "");
  const bundledGateway = gatewayKeyBundle?.gateway ?? null;

  return {
    gatewayKind,
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
    research: {
      firecrawlApiKey: env.FIRECRAWL_API_KEY || "",
      firecrawlBaseUrl: trimSlash(env.FIRECRAWL_BASE_URL || "https://api.firecrawl.dev"),
      perplexityApiKey: env.PERPLEXITY_API_KEY || "",
      perplexityBaseUrl: trimSlash(env.PERPLEXITY_BASE_URL || "https://api.perplexity.ai"),
      perplexityAskModel: env.PERPLEXITY_ASK_MODEL || "sonar-pro",
      openrouterApiKey: env.OPENROUTER_API_KEY || "",
      openrouterBaseUrl: trimSlash(env.OPENROUTER_BASE_URL || "https://openrouter.ai/api/v1"),
      xsearchModel: env.XSEARCH_MODEL || "x-ai/grok-4.3",
      // Declared, never implied: flips to attested-l1 only when this gateway
      // is promoted to attested runtime (Tinfoil) per the connector rule.
      assurance: env.RESEARCH_ASSURANCE || "observed-l1"
    },
    supabase: loadSupabaseConfig(env, publicBaseUrl, dataDir, gatewayKind),
    nango: loadNangoConfig(env),
    nangoSupabase: loadNangoSupabaseConfig(env),
    sharepoint: loadSharepointConfig(env),
    gmail: loadGmailConfig(env),
    kojimem: loadKojimemConfig(env),
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
    connectorCredentials: {
      backend: connectorCredentialStoreBackend,
      filePath: env.CONNECTOR_CREDENTIAL_STORE_PATH || env.SUPABASE_CONNECTOR_STORE_PATH || `${dataDir}/connector-credentials.json`,
      encryptionSecret: env.CONNECTOR_CREDENTIAL_ENCRYPTION_KEY || env.SUPABASE_CONNECTOR_CREDENTIAL_ENCRYPTION_KEY || env.MCP_SESSION_SECRET || sessionSecret,
      dynamoDb: {
        tableName: env.CONNECTOR_CREDENTIAL_DYNAMODB_TABLE || env.SUPABASE_CONNECTOR_DYNAMODB_TABLE || env.OAUTH_DYNAMODB_TABLE || env.OAUTH_DYNAMODB_TABLE_NAME || "",
        awsRegion: env.CONNECTOR_CREDENTIAL_DYNAMODB_AWS_REGION || env.OAUTH_DYNAMODB_AWS_REGION || env.AWS_REGION || "",
        awsAccessKeyId: env.CONNECTOR_CREDENTIAL_DYNAMODB_AWS_ACCESS_KEY_ID || env.OAUTH_DYNAMODB_AWS_ACCESS_KEY_ID || "",
        awsSecretAccessKey: env.CONNECTOR_CREDENTIAL_DYNAMODB_AWS_SECRET_ACCESS_KEY || env.OAUTH_DYNAMODB_AWS_SECRET_ACCESS_KEY || "",
        ttlAttribute: env.CONNECTOR_CREDENTIAL_DYNAMODB_TTL_ATTRIBUTE || env.OAUTH_DYNAMODB_TTL_ATTRIBUTE || "ttl"
      }
    },
    oauth: {
      enabled: Boolean(env.OAUTH_ISSUER),
      issuer: trimSlash(env.OAUTH_ISSUER || publicBaseUrl),
      storeBackend: oauthStoreBackend,
      storePath: env.OAUTH_STORE_PATH || `${dataDir}/oauth-store.json`,
      dynamoDb: {
        tableName: env.OAUTH_DYNAMODB_TABLE || env.OAUTH_DYNAMODB_TABLE_NAME || "",
        awsRegion: env.OAUTH_DYNAMODB_AWS_REGION || env.AWS_REGION || "",
        awsAccessKeyId: env.OAUTH_DYNAMODB_AWS_ACCESS_KEY_ID || "",
        awsSecretAccessKey: env.OAUTH_DYNAMODB_AWS_SECRET_ACCESS_KEY || "",
        ttlAttribute: env.OAUTH_DYNAMODB_TTL_ATTRIBUTE || "ttl"
      },
      consentPassword: env.OAUTH_CONSENT_PASSWORD || "",
      consentPasswordHash: env.SHAREPOINT_MCP_CONSENT_PASSWORD_SHA256 || env.KOJIMEM_MCP_CONSENT_PASSWORD_SHA256 || env.NANGO_SUPABASE_MCP_CONSENT_PASSWORD_SHA256 || env.SUPABASE_MCP_CONSENT_PASSWORD_SHA256 || env.OAUTH_CONSENT_PASSWORD_SHA256 || "",
      accessTokenTtlMs: Number(env.OAUTH_ACCESS_TOKEN_TTL_SECONDS || 3600) * 1000,
      refreshTokenTtlMs: Number(env.OAUTH_REFRESH_TOKEN_TTL_SECONDS || 7 * 24 * 3600) * 1000,
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
    managedAgentPolicy: {
      bundleFile: env.MANAGED_AGENT_POLICY_BUNDLE_FILE || "policies/managed-agent-policy-epoch-001.json",
      bundleUrl: trimSlash(env.MANAGED_AGENT_POLICY_BUNDLE_URL || ""),
      epochId: env.MANAGED_AGENT_POLICY_EPOCH_ID || "managed-agent-policy-epoch-001",
      expectedDigest: env.MANAGED_AGENT_POLICY_BUNDLE_DIGEST || ""
    },
    tenant: {
      id: env.TENANT_ID || "default"
    },
    gateway: {
      id: env.GATEWAY_ID || bundledGateway?.gateway_id || (gatewayKind === "research" ? "gateway:research-mcp" : gatewayKind === "managed-agent-policy" ? "gateway:managed-agent-policy" : gatewayKind === "kojimem" ? "gateway:kojimem-agent-handoff" : gatewayKind === "nango-supabase" ? "gateway:nango-supabase-mcp" : gatewayKind === "supabase" ? "gateway:supabase-mcp" : "gateway:email-mcp"),
      keyId: env.GATEWAY_KEY_ID || bundledGateway?.key_id || (gatewayKind === "research" ? "gateway:research-mcp" : gatewayKind === "managed-agent-policy" ? "gateway:managed-agent-policy" : gatewayKind === "kojimem" ? "gateway:kojimem-agent-handoff" : gatewayKind === "nango-supabase" ? "gateway:nango-supabase-mcp" : gatewayKind === "supabase" ? "gateway:supabase-mcp" : "gateway:email-mcp"),
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
        workflowId: env.WITNESS_WORKFLOW_ID || (gatewayKind === "research" ? "research.read" : gatewayKind === "managed-agent-policy" ? "managed-agent.observed" : gatewayKind === "kojimem" ? "agent-handoff.fraud-signal-exchange" : gatewayKind === "supabase" || gatewayKind === "nango-supabase" ? "supabase.query" : "email.send")
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

function loadSupabaseConfig(env, publicBaseUrl, dataDir, gatewayKind) {
  const readOnlyDefault = env.SUPABASE_MCP_READ_ONLY === undefined ? "true" : env.SUPABASE_MCP_READ_ONLY;
  const features = parseCsv(env.SUPABASE_MCP_FEATURES || "database,docs");
  const oauthRedirectUri = trimSlash(env.SUPABASE_OAUTH_REDIRECT_URI || `${publicBaseUrl}/connectors/supabase/oauth/callback`);
  const nangoServerUrl = trimSlash(env.NANGO_SERVER_URL || "https://api.nango.dev");
  return {
    connectorId: env.SUPABASE_CONNECTOR_ID || env.NANGO_SUPABASE_CONNECTOR_ID || (gatewayKind === "nango-supabase" ? "nango-supabase-pilot" : "supabase-pilot"),
    connectorLabel: env.SUPABASE_CONNECTOR_LABEL || env.NANGO_SUPABASE_CONNECTOR_LABEL || (gatewayKind === "nango-supabase" ? "Nango Supabase Pilot" : "Supabase Pilot"),
    projectRef: env.SUPABASE_PROJECT_REF || env.NANGO_SUPABASE_PROJECT_REF || "",
    readOnly: truthy(readOnlyDefault),
    features,
    mcpBaseUrl: trimSlash(env.SUPABASE_MCP_BASE_URL || (gatewayKind === "nango-supabase" ? `${nangoServerUrl}/proxy/mcp` : "https://mcp.supabase.com/mcp")),
    upstreamCallsEnabled: truthy(env.SUPABASE_ENABLE_UPSTREAM_CALLS || env.SUPABASE_MCP_ENABLE_UPSTREAM_CALLS),
    evidenceMode: env.SUPABASE_EVIDENCE_MODE || "digest-only",
    toolResultMode: env.SUPABASE_TOOL_RESULT_MODE || env.SUPABASE_MCP_RESULT_MODE || "summary",
    toolResultMaxChars: positiveInt(env.SUPABASE_TOOL_RESULT_MAX_CHARS || 20000, "SUPABASE_TOOL_RESULT_MAX_CHARS"),
    maxRows: positiveInt(env.SUPABASE_QUERY_MAX_ROWS || 100, "SUPABASE_QUERY_MAX_ROWS"),
    timeoutMs: positiveInt(env.SUPABASE_QUERY_TIMEOUT_MS || 30000, "SUPABASE_QUERY_TIMEOUT_MS"),
    blockedSchemas: parseCsv(env.SUPABASE_BLOCKED_SCHEMAS || "auth,storage,vault"),
    blockedTables: parseCsv(env.SUPABASE_BLOCKED_TABLES || ""),
    oauth: {
      clientId: env.SUPABASE_OAUTH_CLIENT_ID || "",
      clientSecret: env.SUPABASE_OAUTH_CLIENT_SECRET || "",
      accessToken: env.SUPABASE_OAUTH_ACCESS_TOKEN || "",
      refreshToken: env.SUPABASE_OAUTH_REFRESH_TOKEN || "",
      issuer: trimSlash(env.SUPABASE_OAUTH_ISSUER || "https://mcp.supabase.com"),
      authorizationUrl: trimSlash(env.SUPABASE_OAUTH_AUTHORIZATION_URL || ""),
      tokenUrl: trimSlash(env.SUPABASE_OAUTH_TOKEN_URL || ""),
      tokenAuthMethod: env.SUPABASE_OAUTH_TOKEN_AUTH_METHOD || "client_secret_basic",
      resource: env.SUPABASE_OAUTH_RESOURCE || "",
      redirectUri: oauthRedirectUri,
      scope: env.SUPABASE_OAUTH_SCOPE || "",
      stateSecret: env.SUPABASE_OAUTH_STATE_SECRET || env.MCP_SESSION_SECRET || "",
      storePath: env.SUPABASE_CONNECTOR_STORE_PATH || `${dataDir}/supabase-connector.json`
    }
  };
}

function loadNangoConfig(env) {
  return {
    serverUrl: trimSlash(env.NANGO_SERVER_URL || "https://api.nango.dev"),
    secretKey: env.NANGO_SECRET_KEY || ""
  };
}

function loadNangoSupabaseConfig(env) {
  return {
    providerConfigKey: env.NANGO_SUPABASE_PROVIDER_CONFIG_KEY || env.NANGO_PROVIDER_CONFIG_KEY || "",
    connectionId: env.NANGO_SUPABASE_CONNECTION_ID || env.NANGO_CONNECTION_ID || "",
    projectRef: env.NANGO_SUPABASE_PROJECT_REF || env.SUPABASE_PROJECT_REF || "",
    tag: env.NANGO_SUPABASE_TAG || "nango-supabase-poc",
    endUserId: env.NANGO_SUPABASE_END_USER_ID || "attexa-demo-jason",
    endUserEmail: env.NANGO_SUPABASE_END_USER_EMAIL || "jason@amotivv.com",
    organizationId: env.NANGO_SUPABASE_ORGANIZATION_ID || "amotivv-dev"
  };
}

function loadSharepointConfig(env) {
  return {
    providerConfigKey: env.NANGO_SHAREPOINT_PROVIDER_CONFIG_KEY || "sharepoint-online",
    connectionId: env.NANGO_SHAREPOINT_CONNECTION_ID || "",
    defaultSiteId: env.SHAREPOINT_DEFAULT_SITE_ID || "root",
    maxItems: positiveInt(env.SHAREPOINT_MAX_ITEMS || 50, "SHAREPOINT_MAX_ITEMS"),
    docMaxChars: positiveInt(env.SHAREPOINT_DOC_MAX_CHARS || 40000, "SHAREPOINT_DOC_MAX_CHARS"),
    timeoutMs: positiveInt(env.SHAREPOINT_TIMEOUT_MS || 30000, "SHAREPOINT_TIMEOUT_MS"),
    assurance: env.SHAREPOINT_ASSURANCE || "observed-l1"
  };
}

function loadGmailConfig(env) {
  return {
    providerConfigKey: env.NANGO_GMAIL_INTEGRATION_ID || env.NANGO_GMAIL_PROVIDER_CONFIG_KEY || "google-mail",
    fallbackConnectionId: env.NANGO_GMAIL_CONNECTION_ID || "",
    maxResults: positiveInt(env.GMAIL_MAX_RESULTS || 25, "GMAIL_MAX_RESULTS"),
    bodyMaxChars: positiveInt(env.GMAIL_BODY_MAX_CHARS || 40000, "GMAIL_BODY_MAX_CHARS"),
    timeoutMs: positiveInt(env.GMAIL_TIMEOUT_MS || 30000, "GMAIL_TIMEOUT_MS"),
    assurance: env.GMAIL_ASSURANCE || "observed-l1"
  };
}

function loadKojimemConfig(env) {
  const agentAPrivateKey = env.KOJIMEM_AGENT_A_PRIVATE_KEY || "";
  const agentBPrivateKey = env.KOJIMEM_AGENT_B_PRIVATE_KEY || "";
  return {
    apiBaseUrl: trimSlash(env.KOJIMEM_API_BASE_URL || "https://api.kojimem.dev"),
    network: env.KOJIMEM_NETWORK || "eip155:84532",
    connectorId: env.KOJIMEM_CONNECTOR_ID || "kojimem-agent-handoff",
    connectorLabel: env.KOJIMEM_CONNECTOR_LABEL || "Kojimem Agent Handoff",
    agentAPrivateKey,
    agentBPrivateKey,
    agentAAccount: createKojimemAccount(agentAPrivateKey),
    agentBAccount: createKojimemAccount(agentBPrivateKey),
    agentALabel: env.KOJIMEM_AGENT_A_LABEL || "Conduit - Issuer Fraud Analyst",
    agentBLabel: env.KOJIMEM_AGENT_B_LABEL || "Sentinel - Network Correlator",
    defaultTtl: env.KOJIMEM_DEFAULT_TTL || "1h",
    maxTtl: env.KOJIMEM_MAX_TTL || "1h",
    defaultRecallTier: env.KOJIMEM_DEFAULT_RECALL_TIER || "reasoning",
    defaultEstimatedExposureUsd: Number(env.KOJIMEM_DEFAULT_ESTIMATED_EXPOSURE_USD || 25000),
    l3ExposureThresholdUsd: Number(env.KOJIMEM_L3_EXPOSURE_THRESHOLD_USD || 10000),
    timeoutMs: Number(env.KOJIMEM_TIMEOUT_MS || 90000)
  };
}

export function parseWitnessUrls(value, prefix = "w") {
  return parseCsv(value).map((item, index) => {
    const eq = item.indexOf("=");
    if (eq === -1) {
      return { id: `${prefix}${index + 1}`, url: item };
    }
    const [id, witnessEpochId = "", registryEpochId = "", workflowId = ""] = item.slice(0, eq).trim().split("|").map((part) => part.trim());
    return {
      id,
      url: item.slice(eq + 1).trim(),
      witnessEpochId,
      registryEpochId,
      workflowId
    };
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
    sigstoreBundleRef: env.L1_TINFOIL_SIGSTORE_BUNDLE_REF || "",
    registryEpochUrl: env.L1_WITNESS_REGISTRY_EPOCH_URL || env.WITNESS_REGISTRY_EPOCH_URL || "",
    registryPointerUrl: env.L1_WITNESS_REGISTRY_POINTER_URL || env.WITNESS_REGISTRY_POINTER_URL || "",
    registryTrustAnchorsUrl: env.L1_WITNESS_REGISTRY_TRUST_ANCHORS_URL || env.WITNESS_REGISTRY_TRUST_ANCHORS_URL || "",
    registryEpochDigest: env.L1_WITNESS_REGISTRY_EPOCH_DIGEST || env.WITNESS_REGISTRY_EPOCH_DIGEST || ""
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
    sigstoreBundleRef: item.sigstoreBundleRef || item.sigstore_bundle_ref || "",
    witnessEpochId: item.witnessEpochId || item.witness_epoch_id || "",
    registryEpochId: item.registryEpochId || item.registry_epoch_id || "",
    workflowId: item.workflowId || item.workflow_id || "",
    registryEpochUrl: item.registryEpochUrl || item.registry_epoch_url || "",
    registryPointerUrl: item.registryPointerUrl || item.registry_pointer_url || "",
    registryTrustAnchorsUrl: item.registryTrustAnchorsUrl || item.registry_trust_anchors_url || "",
    registryEpochDigest: item.registryEpochDigest || item.registry_epoch_digest || ""
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

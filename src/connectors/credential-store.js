import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";

const CREDENTIAL_RECORD_VERSION = "strata.connector_credential_record.v1";

export function createConnectorCredentialStore(config) {
  const storeConfig = config.connectorCredentials;
  const codec = new ConnectorCredentialCodec({ secret: storeConfig.encryptionSecret });
  if (storeConfig.backend === "dynamodb") {
    return new ConnectorCredentialDynamoDbStore({ ...storeConfig.dynamoDb, codec });
  }
  if (storeConfig.backend === "file") {
    return new ConnectorCredentialFileStore({ filePath: storeConfig.filePath, codec });
  }
  if (storeConfig.backend === "memory") {
    return new ConnectorCredentialMemoryStore({ codec });
  }
  throw new Error(`Unsupported connector credential store backend: ${storeConfig.backend}`);
}

export function connectorCredentialKey({ tenantId, connectorType, connectorId, subject = "default" }) {
  return `connector#${safeKey(tenantId)}#${safeKey(connectorType)}#${safeKey(connectorId)}#${safeKey(subject)}`;
}

export class ConnectorCredentialMemoryStore {
  constructor({ codec, clock = () => new Date() }) {
    this.codec = codec;
    this.clock = clock;
    this.records = new Map();
  }

  async get(scope) {
    const record = this.records.get(connectorCredentialKey(scope));
    return record ? this.codec.toPublicCredential(record) : null;
  }

  async put(scope, credential, metadata = {}) {
    const record = this.codec.toRecord(scope, credential, metadata, this.clock());
    this.records.set(connectorCredentialKey(scope), record);
    return this.codec.toPublicCredential(record);
  }

  async revoke(scope) {
    const key = connectorCredentialKey(scope);
    const record = this.records.get(key);
    if (record) {
      this.records.set(key, { ...record, revoked: true, revoked_at: this.clock().toISOString() });
    }
  }
}

export class ConnectorCredentialFileStore extends ConnectorCredentialMemoryStore {
  constructor({ filePath, codec, clock = () => new Date() }) {
    super({ codec, clock });
    if (!filePath) {
      throw new Error("ConnectorCredentialFileStore requires filePath");
    }
    this.filePath = filePath;
    this.load();
  }

  async put(scope, credential, metadata = {}) {
    const result = await super.put(scope, credential, metadata);
    this.persist();
    return result;
  }

  async revoke(scope) {
    await super.revoke(scope);
    this.persist();
  }

  load() {
    if (!existsSync(this.filePath)) {
      return;
    }
    const raw = readFileSync(this.filePath, "utf8");
    if (!raw.trim()) {
      return;
    }
    const state = JSON.parse(raw);
    this.records = new Map((state.records || []).map((record) => [record.pk, record]));
  }

  persist() {
    mkdirSync(dirname(this.filePath), { recursive: true });
    const state = {
      version: "strata.connector_credential_store.v1",
      saved_at: new Date().toISOString(),
      records: [...this.records.values()]
    };
    const tmpPath = `${this.filePath}.${process.pid}.tmp`;
    writeFileSync(tmpPath, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    renameSync(tmpPath, this.filePath);
  }
}

export class ConnectorCredentialDynamoDbStore {
  constructor({ tableName, awsRegion = "", awsAccessKeyId = "", awsSecretAccessKey = "", ttlAttribute = "ttl", codec, clock = () => new Date() }) {
    if (!tableName) {
      throw new Error("ConnectorCredentialDynamoDbStore requires tableName");
    }
    if ((awsAccessKeyId && !awsSecretAccessKey) || (!awsAccessKeyId && awsSecretAccessKey)) {
      throw new Error("ConnectorCredentialDynamoDbStore requires both AWS access key id and secret access key when either is set");
    }
    const clientOptions = {};
    if (awsRegion) {
      clientOptions.region = awsRegion;
    }
    if (awsAccessKeyId && awsSecretAccessKey) {
      clientOptions.credentials = { accessKeyId: awsAccessKeyId, secretAccessKey: awsSecretAccessKey };
    }
    this.tableName = tableName;
    this.ttlAttribute = ttlAttribute;
    this.codec = codec;
    this.clock = clock;
    this.db = DynamoDBDocumentClient.from(new DynamoDBClient(clientOptions), {
      marshallOptions: { removeUndefinedValues: true }
    });
  }

  async get(scope) {
    const result = await this.db.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk: connectorCredentialKey(scope) }
    }));
    if (!result.Item || result.Item.revoked) {
      return null;
    }
    return this.codec.toPublicCredential(result.Item);
  }

  async put(scope, credential, metadata = {}) {
    const record = this.codec.toRecord(scope, credential, metadata, this.clock());
    await this.db.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        ...record,
        kind: "connector_credential"
      }
    }));
    return this.codec.toPublicCredential(record);
  }

  async revoke(scope) {
    try {
      await this.db.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: connectorCredentialKey(scope) },
        UpdateExpression: "SET #revoked = :true, #revokedAt = :revokedAt",
        ConditionExpression: "attribute_exists(pk)",
        ExpressionAttributeNames: { "#revoked": "revoked", "#revokedAt": "revoked_at" },
        ExpressionAttributeValues: { ":true": true, ":revokedAt": this.clock().toISOString() }
      }));
    } catch (error) {
      if (error?.name !== "ConditionalCheckFailedException") {
        throw error;
      }
    }
  }
}

class ConnectorCredentialCodec {
  constructor({ secret }) {
    if (!secret) {
      throw new Error("Connector credential encryption secret is required");
    }
    this.key = createHash("sha256").update(String(secret)).digest();
    this.keyId = `sha256:${createHash("sha256").update(this.key).digest("hex").slice(0, 16)}`;
  }

  toRecord(scope, credential, metadata, now) {
    const pk = connectorCredentialKey(scope);
    const encrypted = encryptJson(credential, this.key);
    return {
      version: CREDENTIAL_RECORD_VERSION,
      pk,
      tenant_id: scope.tenantId,
      connector_type: scope.connectorType,
      connector_id: scope.connectorId,
      subject: scope.subject || "default",
      saved_at: now.toISOString(),
      expires_at: credential.expires_at || null,
      token_type: credential.token_type || "Bearer",
      scope: credential.scope || "",
      credential_fingerprint: credentialFingerprint(credential),
      encryption: { ...encrypted, key_id: this.keyId },
      metadata,
      revoked: false
    };
  }

  toPublicCredential(record) {
    return {
      ...decryptJson(record.encryption, this.key),
      token_type: record.token_type || "Bearer",
      scope: record.scope || "",
      expires_at: record.expires_at || null,
      credential_fingerprint: record.credential_fingerprint || null,
      saved_at: record.saved_at || null,
      connector_id: record.connector_id,
      connector_type: record.connector_type,
      tenant_id: record.tenant_id,
      subject: record.subject || "default"
    };
  }
}

function encryptJson(value, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    algorithm: "aes-256-gcm",
    iv: iv.toString("base64url"),
    tag: tag.toString("base64url"),
    ciphertext: ciphertext.toString("base64url")
  };
}

function decryptJson(envelope, key) {
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64url"));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
    decipher.final()
  ]);
  return JSON.parse(plaintext.toString("utf8"));
}

function credentialFingerprint(credential) {
  const source = credential.refresh_token || credential.access_token || "";
  return source ? `sha256:${createHash("sha256").update(source).digest("hex")}` : null;
}

function safeKey(value) {
  return encodeURIComponent(String(value || "default"));
}

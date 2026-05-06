import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";

export class OAuthMemoryStore {
  constructor(clock = () => new Date()) {
    this.clock = clock;
    this.clients = new Map();
    this.codes = new Map();
    this.accessTokens = new Map();
    this.refreshTokens = new Map();
  }

  saveClient(client) {
    this.clients.set(client.client_id, client);
    return client;
  }

  getClient(clientId) {
    return this.clients.get(clientId) || null;
  }

  saveCode(code) {
    this.codes.set(code.code, code);
    return code;
  }

  consumeCode(codeValue) {
    const code = this.codes.get(codeValue);
    if (!code || code.used || code.expires_at < this.clock().getTime()) {
      return null;
    }
    code.used = true;
    return code;
  }

  saveAccessToken(token) {
    this.accessTokens.set(token.access_token, token);
    return token;
  }

  getAccessToken(value) {
    const token = this.accessTokens.get(value);
    if (!token || token.revoked || token.expires_at < this.clock().getTime()) {
      return null;
    }
    return token;
  }

  saveRefreshToken(token) {
    this.refreshTokens.set(token.refresh_token, token);
    return token;
  }

  consumeRefreshToken(value) {
    const token = this.refreshTokens.get(value);
    if (!token || token.revoked || token.expires_at < this.clock().getTime()) {
      return null;
    }
    token.revoked = true;
    return token;
  }

  revoke(value) {
    const access = this.accessTokens.get(value);
    if (access) {
      access.revoked = true;
    }
    const refresh = this.refreshTokens.get(value);
    if (refresh) {
      refresh.revoked = true;
    }
  }
}

export class OAuthFileStore extends OAuthMemoryStore {
  constructor({ filePath, clock = () => new Date() }) {
    super(clock);
    if (!filePath) {
      throw new Error("OAuthFileStore requires filePath");
    }
    this.filePath = filePath;
    this.load();
  }

  saveClient(client) {
    const result = super.saveClient(client);
    this.persist();
    return result;
  }

  saveCode(code) {
    const result = super.saveCode(code);
    this.persist();
    return result;
  }

  consumeCode(codeValue) {
    const result = super.consumeCode(codeValue);
    if (result) {
      this.persist();
    }
    return result;
  }

  saveAccessToken(token) {
    const result = super.saveAccessToken(token);
    this.persist();
    return result;
  }

  saveRefreshToken(token) {
    const result = super.saveRefreshToken(token);
    this.persist();
    return result;
  }

  consumeRefreshToken(value) {
    const result = super.consumeRefreshToken(value);
    if (result) {
      this.persist();
    }
    return result;
  }

  revoke(value) {
    super.revoke(value);
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
    this.clients = mapFromEntries(state.clients, "client_id");
    this.codes = mapFromEntries(state.codes, "code");
    this.accessTokens = mapFromEntries(state.access_tokens, "access_token");
    this.refreshTokens = mapFromEntries(state.refresh_tokens, "refresh_token");
  }

  persist() {
    mkdirSync(dirname(this.filePath), { recursive: true });
    const state = {
      version: "strata.oauth.store.v1",
      saved_at: new Date().toISOString(),
      clients: [...this.clients.values()],
      codes: [...this.codes.values()],
      access_tokens: [...this.accessTokens.values()],
      refresh_tokens: [...this.refreshTokens.values()]
    };
    const tmpPath = `${this.filePath}.${process.pid}.tmp`;
    writeFileSync(tmpPath, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    renameSync(tmpPath, this.filePath);
  }
}

export class OAuthDynamoDbStore {
  constructor({ tableName, awsRegion = "", awsAccessKeyId = "", awsSecretAccessKey = "", ttlAttribute = "ttl", clock = () => new Date() }) {
    if (!tableName) {
      throw new Error("OAuthDynamoDbStore requires tableName");
    }
    if ((awsAccessKeyId && !awsSecretAccessKey) || (!awsAccessKeyId && awsSecretAccessKey)) {
      throw new Error("OAuthDynamoDbStore requires both AWS access key id and secret access key when either is set");
    }
    const clientOptions = {};
    if (awsRegion) {
      clientOptions.region = awsRegion;
    }
    if (awsAccessKeyId && awsSecretAccessKey) {
      clientOptions.credentials = {
        accessKeyId: awsAccessKeyId,
        secretAccessKey: awsSecretAccessKey
      };
    }
    this.tableName = tableName;
    this.ttlAttribute = ttlAttribute;
    this.clock = clock;
    this.db = DynamoDBDocumentClient.from(new DynamoDBClient(clientOptions), {
      marshallOptions: { removeUndefinedValues: true }
    });
  }

  async saveClient(client) {
    await this.putRecord(this.key("client", client.client_id), "client", client);
    return client;
  }

  async getClient(clientId) {
    return this.getRecord(this.key("client", clientId));
  }

  async saveCode(code) {
    await this.putRecord(this.key("code", code.code), "code", code);
    return code;
  }

  async consumeCode(codeValue) {
    return this.consumeRecord(this.key("code", codeValue), "used");
  }

  async saveAccessToken(token) {
    await this.putRecord(this.key("access", token.access_token), "access", token);
    return token;
  }

  async getAccessToken(value) {
    const token = await this.getRecord(this.key("access", value));
    if (!token || token.revoked || token.expires_at < this.clock().getTime()) {
      return null;
    }
    return { ...token, access_token: value };
  }

  async saveRefreshToken(token) {
    await this.putRecord(this.key("refresh", token.refresh_token), "refresh", token);
    return token;
  }

  async consumeRefreshToken(value) {
    return this.consumeRecord(this.key("refresh", value), "revoked");
  }

  async revoke(value) {
    await Promise.all([
      this.markRevoked(this.key("access", value)),
      this.markRevoked(this.key("refresh", value))
    ]);
  }

  key(kind, value) {
    if (["code", "access", "refresh"].includes(kind)) {
      return `${kind}#${sha256Hex(value)}`;
    }
    return `${kind}#${value}`;
  }

  async getRecord(pk) {
    const result = await this.db.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk }
    }));
    return this.toRecord(result.Item);
  }

  async putRecord(pk, kind, record) {
    const ttl = record.expires_at ? Math.ceil(record.expires_at / 1000) : undefined;
    await this.db.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        pk,
        kind,
        ...this.toStoredRecord(kind, record),
        ...(ttl ? { [this.ttlAttribute]: ttl } : {})
      }
    }));
  }

  toStoredRecord(kind, record) {
    if (kind === "code") {
      const { code: _code, ...stored } = record;
      return stored;
    }
    if (kind === "access") {
      const { access_token: _accessToken, ...stored } = record;
      return stored;
    }
    if (kind === "refresh") {
      const { refresh_token: _refreshToken, ...stored } = record;
      return stored;
    }
    return record;
  }

  async consumeRecord(pk, consumedField) {
    try {
      const result = await this.db.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk },
        UpdateExpression: "SET #consumed = :true",
        ConditionExpression: "attribute_exists(pk) AND (attribute_not_exists(#consumed) OR #consumed = :false) AND #expiresAt > :now",
        ExpressionAttributeNames: {
          "#consumed": consumedField,
          "#expiresAt": "expires_at"
        },
        ExpressionAttributeValues: {
          ":true": true,
          ":false": false,
          ":now": this.clock().getTime()
        },
        ReturnValues: "ALL_NEW"
      }));
      return this.toRecord(result.Attributes);
    } catch (error) {
      if (isConditionalCheckFailed(error)) {
        return null;
      }
      throw error;
    }
  }

  async markRevoked(pk) {
    try {
      await this.db.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk },
        UpdateExpression: "SET #revoked = :true",
        ConditionExpression: "attribute_exists(pk)",
        ExpressionAttributeNames: { "#revoked": "revoked" },
        ExpressionAttributeValues: { ":true": true }
      }));
    } catch (error) {
      if (!isConditionalCheckFailed(error)) {
        throw error;
      }
    }
  }

  toRecord(item) {
    if (!item) {
      return null;
    }
    const { pk: _pk, kind: _kind, [this.ttlAttribute]: _ttl, ...record } = item;
    return record;
  }
}

export function randomToken(prefix) {
  return `${prefix}_${randomBytes(32).toString("base64url")}`;
}

function isConditionalCheckFailed(error) {
  return error?.name === "ConditionalCheckFailedException";
}

function sha256Hex(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function mapFromEntries(entries, key) {
  const map = new Map();
  for (const entry of entries || []) {
    if (entry?.[key]) {
      map.set(entry[key], entry);
    }
  }
  return map;
}

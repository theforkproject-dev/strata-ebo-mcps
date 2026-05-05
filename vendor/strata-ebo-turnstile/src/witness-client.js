import { randomUUID } from "node:crypto";
import { createWitnessSignRequest } from "./witness-request.js";

export class HttpWitnessClient {
  constructor({ id, url, signedRequests = null }) {
    this.id = id;
    this.url = url.replace(/\/$/, "");
    this.signedRequests = signedRequests?.enabled ? {
      ttlMs: 60_000,
      clock: () => new Date(),
      requestIdFactory: () => `req_${randomUUID()}`,
      witnessId: id,
      ...signedRequests
    } : null;
  }

  async sign(subject) {
    if (this.signedRequests) {
      return this.signRequest(subject);
    }

    const response = await fetch(`${this.url}/v1/sign`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subject })
    });
    const body = await response.json();

    if (!response.ok) {
      throw new Error(body.error ?? `witness ${this.id} returned ${response.status}`);
    }

    return body.signature;
  }

  async signRequest(subject) {
    const config = this.signedRequests;
    this.requireSignedRequestConfig(config);
    const issuedAt = config.clock().toISOString();
    const request = createWitnessSignRequest({
      requestId: config.requestIdFactory(),
      issuedAt,
      ttlMs: config.ttlMs,
      gatewayId: config.gatewayId,
      gatewayKeyId: config.gatewayKeyId ?? config.gatewaySigner.keyId,
      witnessId: config.witnessId,
      witnessEpochId: config.witnessEpochId,
      registryEpochId: config.registryEpochId,
      workflowId: config.workflowId,
      subject
    }, config.gatewaySigner);

    const response = await fetch(`${this.url}/v1/sign-request`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request)
    });
    const body = await response.json();

    if (!response.ok) {
      const error = new Error(body.error ?? `witness ${this.id} returned ${response.status}`);
      error.code = body.code ?? null;
      error.status = response.status;
      throw error;
    }

    return body.signature;
  }

  async publicKey() {
    const response = await fetch(`${this.url}/v1/public-key`);
    const body = await response.json();

    if (!response.ok) {
      throw new Error(body.error ?? `witness ${this.id} returned ${response.status}`);
    }

    return body;
  }

  requireSignedRequestConfig(config) {
    if (!config) {
      throw new Error("signed witness request client is not enabled");
    }

    const missing = [];
    for (const [field, value] of Object.entries({
      gatewayId: config.gatewayId,
      gatewaySigner: config.gatewaySigner,
      witnessId: config.witnessId,
      witnessEpochId: config.witnessEpochId,
      registryEpochId: config.registryEpochId,
      workflowId: config.workflowId
    })) {
      if (!value) {
        missing.push(field);
      }
    }

    if (missing.length > 0) {
      throw new Error(`signed witness request client missing config: ${missing.join(", ")}`);
    }
  }
}

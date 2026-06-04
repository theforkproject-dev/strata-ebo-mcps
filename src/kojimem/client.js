import axios from "axios";
import { x402Client, wrapAxiosWithPayment } from "@x402/axios";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { buildSIWXHeader } from "./siwx.js";

export function createKojimemAccount(privateKey) {
  if (!privateKey) return null;
  return privateKeyToAccount(privateKey.startsWith("0x") ? privateKey : `0x${privateKey}`);
}

export class KojimemAgentClient {
  constructor({ apiBaseUrl, account, timeoutMs = 90_000 }) {
    if (!account) throw new Error("KojimemAgentClient requires an account");
    this.apiBaseUrl = String(apiBaseUrl || "https://api.kojimem.dev").replace(/\/$/, "");
    this.account = account;
    this.timeoutMs = timeoutMs;

    const paymentClient = new x402Client();
    registerExactEvmScheme(paymentClient, { signer: account });
    this.paidApi = wrapAxiosWithPayment(axios.create({ baseURL: this.apiBaseUrl, timeout: this.timeoutMs }), paymentClient);
    this.freeApi = axios.create({ baseURL: this.apiBaseUrl, timeout: this.timeoutMs });
  }

  async createMemory({ persona = "research", ttl = "1h", instructions = undefined } = {}) {
    const body = { persona, ttl };
    if (instructions) body.instructions = instructions;
    const res = await this.paidApi.post("/v1/memories", body);
    return res.data;
  }

  async writeFacts(memoryId, facts) {
    await this.freeApi.post(`/v1/memories/${encodeURIComponent(memoryId)}/facts`, {
      facts: Array.isArray(facts) ? facts.map(String) : []
    }, {
      headers: { "X-SIWX": await buildSIWXHeader(this.account) }
    });
    return { ok: true, facts_count: Array.isArray(facts) ? facts.length : 0 };
  }

  async createDelegation(memoryId, { delegate, actions, expires_at = undefined, max_tier = undefined }) {
    const body = { delegate, actions };
    if (expires_at) body.expires_at = expires_at;
    if (max_tier) body.max_tier = max_tier;
    const res = await this.freeApi.post(`/v1/memories/${encodeURIComponent(memoryId)}/delegations/create`, body, {
      headers: { "X-SIWX": await buildSIWXHeader(this.account) }
    });
    return res.data;
  }

  async recall(memoryId, { question, tier = "balanced", delegation = "" }) {
    const headers = delegation ? { "X-Delegation": delegation } : {};
    const res = await this.paidApi.post(`/v1/memories/${encodeURIComponent(memoryId)}/recall/${tier}`, { question }, { headers });
    return res.data;
  }

  async destroy(memoryId, { delegation = "" } = {}) {
    const headers = { "X-SIWX": await buildSIWXHeader(this.account) };
    if (delegation) headers["X-Delegation"] = delegation;
    await this.freeApi.delete(`/v1/memories/${encodeURIComponent(memoryId)}`, { headers });
    return { ok: true };
  }
}

export function axiosErrorMessage(error) {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status || "network_error";
    const body = error.response?.data;
    const message = body?.error?.message || body?.error || error.message;
    return `kojimem ${status}: ${message}`;
  }
  return error instanceof Error ? error.message : String(error);
}

import { randomBytes } from "node:crypto";

export async function buildSIWXHeader(account) {
  const wallet = account.address.toLowerCase();
  const timestamp = new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const nonce = randomBytes(16).toString("hex");
  const message = `kojimem:auth:${wallet}:${timestamp}:${nonce}`;
  const signature = await account.signMessage({ message });
  return Buffer.from(JSON.stringify({ wallet, timestamp, nonce, signature })).toString("base64url");
}

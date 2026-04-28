export class HttpWitnessClient {
  constructor({ id, url }) {
    this.id = id;
    this.url = url.replace(/\/$/, "");
  }

  async sign(subject) {
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

  async publicKey() {
    const response = await fetch(`${this.url}/v1/public-key`);
    const body = await response.json();

    if (!response.ok) {
      throw new Error(body.error ?? `witness ${this.id} returned ${response.status}`);
    }

    return body;
  }
}

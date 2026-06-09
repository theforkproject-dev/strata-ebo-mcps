import {
  collectManagedAgentPolicyQuorum,
  defaultManagedAgentPolicyBundle,
  loadManagedAgentPolicyBundle,
  managedAgentPolicyBundleDigest,
  MANAGED_AGENT_POLICY_DOMAIN
} from "./policy/managed-agent-policy.js";

export class ManagedAgentPolicyGateway {
  constructor(config) {
    this.config = config;
    this.serverName = "attexa-managed-agent-policy-gateway";
    this.serverTitle = "Attexa Managed Agent Policy Gateway";
    this.policyBundlePromise = null;
  }

  async health() {
    const policyBundle = await this.policyBundle();
    const policyDigest = managedAgentPolicyBundleDigest(policyBundle);
    const policyWitnesses = await Promise.all(this.config.policyWitnesses.map((witness) => checkPolicyWitness(witness)));
    const healthyPolicyWitnesses = policyWitnesses.filter((witness) => witness.ok).length;
    return {
      ok: true,
      name: this.serverName,
      gateway_kind: this.config.gatewayKind,
      status: healthyPolicyWitnesses >= this.config.policyWitness.threshold ? "ready" : "not_ready",
      checked_at: new Date().toISOString(),
      policy: {
        policy_bundle_version: policyBundle.version,
        policy_id: policyBundle.policy_id,
        policy_epoch_id: policyBundle.epoch_id,
        policy_bundle_digest: policyDigest,
        policy_url: this.config.managedAgentPolicy.bundleUrl || null,
        domains: policyBundle.domains || [MANAGED_AGENT_POLICY_DOMAIN],
        rules: policyBundle.rules
      },
      assurance: {
        mode: "policy-confirmation-enforcement",
        witness_tiers: ["level-2-policy"],
        policy_witness_quorum_required: `${this.config.policyWitness.threshold}-of-${this.config.policyWitnesses.length}`,
        policy_witness_quorum_available: `${healthyPolicyWitnesses}-of-${this.config.policyWitnesses.length}`
      },
      policy_witnesses: policyWitnesses,
      enforcement_boundary: {
        built_in_claude_tools: "policy decision before user.tool_confirmation",
        external_consequential_actions: "route through a full Attexa Verified Actions gateway"
      }
    };
  }

  async evaluate(body = {}) {
    if (!body.request) {
      const err = new Error("request is required for Managed Agent policy evaluation");
      err.status = 400;
      throw err;
    }
    const policyBundle = await this.policyBundle();
    const expectedPolicyDigest = managedAgentPolicyBundleDigest(policyBundle);
    if (body.policy_bundle_digest && body.policy_bundle_digest !== expectedPolicyDigest) {
      const err = new Error("policy_bundle_digest mismatch");
      err.status = 409;
      err.policy_bundle_digest = expectedPolicyDigest;
      throw err;
    }
    if (body.policy_epoch_id && body.policy_epoch_id !== policyBundle.epoch_id) {
      const err = new Error("policy_epoch_id mismatch");
      err.status = 409;
      err.policy_epoch_id = policyBundle.epoch_id;
      throw err;
    }
    const quorum = await collectManagedAgentPolicyQuorum({
      witnesses: this.config.policyWitnesses,
      request: body.request,
      policyBundle,
      policyUrl: body.policy_url || this.config.managedAgentPolicy.bundleUrl,
      threshold: this.config.policyWitness.threshold
    });
    return {
      ok: quorum.decisions.length >= this.config.policyWitness.threshold,
      domain: body.domain || body.request.domain || MANAGED_AGENT_POLICY_DOMAIN,
      policy_bundle_digest: expectedPolicyDigest,
      policy_epoch_id: policyBundle.epoch_id,
      policy_url: body.policy_url || this.config.managedAgentPolicy.bundleUrl || null,
      quorum,
      decision: quorum.decision,
      request_digest: quorum.request_digest
    };
  }

  async policyBundle() {
    if (!this.policyBundlePromise) {
      this.policyBundlePromise = this.config.managedAgentPolicy.bundleUrl
        ? loadManagedAgentPolicyBundle({ url: this.config.managedAgentPolicy.bundleUrl })
        : Promise.resolve(defaultManagedAgentPolicyBundle());
    }
    return this.policyBundlePromise;
  }
}

async function checkPolicyWitness(witness) {
  const baseUrl = witness.url.replace(/\/$/, "");
  try {
    const response = await fetch(`${baseUrl}/health`);
    const body = await response.json();
    return {
      witness_id: witness.id,
      url: witness.url,
      ok: response.ok && (body.supported_policy_domains || []).includes(MANAGED_AGENT_POLICY_DOMAIN),
      status: response.status,
      policy_bundle_digest: body.policies?.managed_agent?.policy_bundle_digest || null,
      supported_policy_domains: body.supported_policy_domains || []
    };
  } catch (error) {
    return { witness_id: witness.id, url: witness.url, ok: false, error: error.message };
  }
}

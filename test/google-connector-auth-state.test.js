import assert from "node:assert/strict";
import test from "node:test";

import { createGdriveConnectSession, getGdriveConnectionState, resolveGdriveConnection } from "../src/gdrive/client.js";
import { createGmailConnectSession, getGmailConnectionState, resolveGmailConnection } from "../src/gmail/client.js";

function connectionList(connections) {
  return async () => ({
    ok: true,
    json: async () => ({ connections })
  });
}

function connectionWithCanary(connections, canaryStatus) {
  return async (url) => {
    if (String(url).endsWith("/connection")) {
      return { ok: true, status: 200, json: async () => ({ connections }) };
    }
    return {
      ok: canaryStatus >= 200 && canaryStatus < 300,
      status: canaryStatus,
      body: null,
      json: async () => ({}),
    };
  };
}

test("Google Drive auth errors fail closed instead of using the org fallback", async () => {
  const config = {
    nango: { secretKey: "secret", serverUrl: "https://nango.test" },
    gdrive: { providerConfigKey: "google-drive", fallbackConnectionId: "org-drive" }
  };
  const connectionId = await resolveGdriveConnection(config, "user-drive-broken", {
    fetchImpl: connectionWithCanary([{
      provider_config_key: "google-drive",
      connection_id: "broken-drive",
      end_user: { id: "user-drive-broken" },
      errors: [{ type: "auth" }]
    }], 401)
  });

  assert.equal(connectionId, null);
  const state = await getGdriveConnectionState(config, "user-drive-broken-state", {
    fetchImpl: connectionWithCanary([{
      provider_config_key: "google-drive",
      connection_id: "broken-drive-state",
      end_user: { id: "user-drive-broken-state" },
      errors: [{ type: "auth" }]
    }], 401)
  });
  assert.deepEqual(state, {
    status: "reconnect_required",
    connectionId: null,
    existingConnectionId: "broken-drive-state"
  });
});

test("Gmail auth errors fail closed instead of using the org fallback", async () => {
  const config = {
    nango: { secretKey: "secret", serverUrl: "https://nango.test" },
    gmail: { providerConfigKey: "google-mail", fallbackConnectionId: "org-mail" }
  };
  const connectionId = await resolveGmailConnection(config, "user-mail-broken", {
    fetchImpl: connectionWithCanary([{
      provider_config_key: "google-mail",
      connection_id: "broken-mail",
      end_user: { id: "user-mail-broken" },
      errors: [{ type: "auth" }]
    }], 401)
  });

  assert.equal(connectionId, null);
  const state = await getGmailConnectionState(config, "user-mail-broken-state", {
    fetchImpl: connectionWithCanary([{
      provider_config_key: "google-mail",
      connection_id: "broken-mail-state",
      end_user: { id: "user-mail-broken-state" },
      errors: [{ type: "auth" }]
    }], 401)
  });
  assert.deepEqual(state, {
    status: "reconnect_required",
    connectionId: null,
    existingConnectionId: "broken-mail-state"
  });
});

test("historical Google auth errors do not force reconnect when the live connection works", async () => {
  const driveConfig = {
    nango: { secretKey: "secret", serverUrl: "https://nango.test" },
    gdrive: { providerConfigKey: "google-drive" }
  };
  const mailConfig = {
    nango: { secretKey: "secret", serverUrl: "https://nango.test" },
    gmail: { providerConfigKey: "google-mail" }
  };
  const driveState = await getGdriveConnectionState(driveConfig, "user-drive-recovered", {
    fetchImpl: connectionWithCanary([{
      provider_config_key: "google-drive",
      connection_id: "recovered-drive",
      end_user: { id: "user-drive-recovered" },
      errors: [{ type: "auth" }]
    }], 200)
  });
  const mailState = await getGmailConnectionState(mailConfig, "user-mail-recovered", {
    fetchImpl: connectionWithCanary([{
      provider_config_key: "google-mail",
      connection_id: "recovered-mail",
      end_user: { id: "user-mail-recovered" },
      errors: [{ type: "auth" }]
    }], 200)
  });

  assert.deepEqual(driveState, { status: "ready", connectionId: "recovered-drive", existingConnectionId: "recovered-drive" });
  assert.deepEqual(mailState, { status: "ready", connectionId: "recovered-mail", existingConnectionId: "recovered-mail" });
});

test("healthy exact Google connections still resolve normally", async () => {
  const driveConfig = {
    nango: { secretKey: "secret", serverUrl: "https://nango.test" },
    gdrive: { providerConfigKey: "google-drive", fallbackConnectionId: "org-drive" }
  };
  const mailConfig = {
    nango: { secretKey: "secret", serverUrl: "https://nango.test" },
    gmail: { providerConfigKey: "google-mail", fallbackConnectionId: "org-mail" }
  };

  assert.equal(
    await resolveGdriveConnection(driveConfig, "user-drive-healthy", {
      fetchImpl: connectionList([{
        provider_config_key: "google-drive",
        connection_id: "user-drive",
        end_user: { id: "user-drive-healthy" },
        errors: []
      }])
    }),
    "user-drive"
  );
  assert.equal(
    await resolveGmailConnection(mailConfig, "user-mail-healthy", {
      fetchImpl: connectionList([{
        provider_config_key: "google-mail",
        connection_id: "user-mail",
        end_user: { id: "user-mail-healthy" },
        errors: []
      }])
    }),
    "user-mail"
  );
});

test("broken Google connections use Nango reconnect sessions", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, body: JSON.parse(options.body) });
    return { ok: true, json: async () => ({ data: { connect_link: "https://connect.nango.dev/reconnect" } }) };
  };
  const driveConfig = {
    nango: { secretKey: "secret", serverUrl: "https://nango.test" },
    gdrive: { providerConfigKey: "google-drive" }
  };
  const mailConfig = {
    nango: { secretKey: "secret", serverUrl: "https://nango.test" },
    gmail: { providerConfigKey: "google-mail" }
  };

  await createGdriveConnectSession(driveConfig, { endUserId: "drive-user", connectionId: "drive-connection" }, { fetchImpl });
  await createGmailConnectSession(mailConfig, { endUserId: "mail-user", connectionId: "mail-connection" }, { fetchImpl });

  assert.deepEqual(calls, [
    {
      url: "https://nango.test/connect/sessions/reconnect",
      body: { connection_id: "drive-connection", integration_id: "google-drive" }
    },
    {
      url: "https://nango.test/connect/sessions/reconnect",
      body: { connection_id: "mail-connection", integration_id: "google-mail" }
    }
  ]);
});

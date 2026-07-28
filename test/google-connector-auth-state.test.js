import assert from "node:assert/strict";
import test from "node:test";

import { resolveGdriveConnection } from "../src/gdrive/client.js";
import { resolveGmailConnection } from "../src/gmail/client.js";

function connectionList(connections) {
  return async () => ({
    ok: true,
    json: async () => ({ connections })
  });
}

test("Google Drive auth errors fail closed instead of using the org fallback", async () => {
  const config = {
    nango: { secretKey: "secret", serverUrl: "https://nango.test" },
    gdrive: { providerConfigKey: "google-drive", fallbackConnectionId: "org-drive" }
  };
  const connectionId = await resolveGdriveConnection(config, "user-drive-broken", {
    fetchImpl: connectionList([{
      provider_config_key: "google-drive",
      connection_id: "broken-drive",
      end_user: { id: "user-drive-broken" },
      errors: [{ type: "auth" }]
    }])
  });

  assert.equal(connectionId, null);
});

test("Gmail auth errors fail closed instead of using the org fallback", async () => {
  const config = {
    nango: { secretKey: "secret", serverUrl: "https://nango.test" },
    gmail: { providerConfigKey: "google-mail", fallbackConnectionId: "org-mail" }
  };
  const connectionId = await resolveGmailConnection(config, "user-mail-broken", {
    fetchImpl: connectionList([{
      provider_config_key: "google-mail",
      connection_id: "broken-mail",
      end_user: { id: "user-mail-broken" },
      errors: [{ type: "auth" }]
    }])
  });

  assert.equal(connectionId, null);
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

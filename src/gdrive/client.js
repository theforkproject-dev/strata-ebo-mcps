import { googleConfigured, getGoogleConnectionState, resolveGoogleConnection, createGoogleConnectSession, googleProxy } from "../google/client.js";

export const gdriveConfigured = (config) => googleConfigured(config, "gdrive");
export const getGdriveConnectionState = (config, subject, options) => getGoogleConnectionState(config, "gdrive", subject, options);
export const resolveGdriveConnection = (config, subject, options) => resolveGoogleConnection(config, "gdrive", subject, options);
export const createGdriveConnectSession = (config, { endUserId, ...input }, options) =>
  createGoogleConnectSession(config, "gdrive", { ...input, subject: endUserId }, options);
// connectionId is now an internal owner-bound reference, never a model argument.
export const gdriveProxy = (config, { connectionId, ...input }, options) =>
  googleProxy(config, "gdrive", { ...input, connection: connectionId }, options);

import { googleConfigured, getGoogleConnectionState, resolveGoogleConnection, createGoogleConnectSession, googleProxy } from "../google/client.js";

export const gmailConfigured = (config) => googleConfigured(config, "gmail");
export const getGmailConnectionState = (config, subject, options) => getGoogleConnectionState(config, "gmail", subject, options);
export const resolveGmailConnection = (config, subject, options) => resolveGoogleConnection(config, "gmail", subject, options);
export const createGmailConnectSession = (config, { endUserId, ...input }, options) =>
  createGoogleConnectSession(config, "gmail", { ...input, subject: endUserId }, options);
// connectionId is now an internal owner-bound reference, never a model argument.
export const gmailProxy = (config, { connectionId, ...input }, options) =>
  googleProxy(config, "gmail", { ...input, connection: connectionId }, options);

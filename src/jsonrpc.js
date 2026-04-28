export const JSON_RPC_VERSION = "2.0";

export function parseJsonRpc(raw) {
  if (!raw || raw.length === 0) {
    throw rpcError(-32700, "empty request body");
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw rpcError(-32700, `Parse error: ${error.message}`);
  }
  if (Array.isArray(parsed)) {
    if (parsed.length === 0) {
      throw rpcError(-32600, "empty batch");
    }
    return parsed;
  }
  return parsed;
}

export function validateRequest(request) {
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    throw rpcError(-32600, "request must be an object");
  }
  if (request.jsonrpc !== JSON_RPC_VERSION) {
    throw rpcError(-32600, 'jsonrpc must be "2.0"');
  }
  if (!request.method || typeof request.method !== "string") {
    throw rpcError(-32600, "method is required");
  }
}

export function successResponse(id, result) {
  return { jsonrpc: JSON_RPC_VERSION, id, result };
}

export function errorResponse(id, error) {
  return {
    jsonrpc: JSON_RPC_VERSION,
    id,
    error: {
      code: error.code || -32603,
      message: error.message || "Internal error",
      ...(error.data ? { data: error.data } : {})
    }
  };
}

export function rpcError(code, message, data = undefined) {
  const error = new Error(message);
  error.code = code;
  if (data !== undefined) {
    error.data = data;
  }
  return error;
}

export function isNotification(request) {
  return request.id === undefined || request.id === null;
}

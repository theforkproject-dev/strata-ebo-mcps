import { canonicalize } from "./canonicalize.js";
import { sha256Hex } from "./crypto.js";

export function digestValue(value) {
  return sha256Hex(canonicalize(value));
}

export function modelRequestDigest({ model, prompt, parameters = {} }) {
  return digestValue({
    action_type: "model.call",
    model,
    parameters,
    prompt
  });
}

export function dataQueryDigest({ source, query, parameters = {} }) {
  return digestValue({
    action_type: "data.query",
    parameters,
    query,
    source
  });
}

export function humanApprovalDigest({ approver, question, context = {} }) {
  return digestValue({
    action_type: "human.approval",
    approver,
    context,
    question
  });
}

export function toolRequestDigest({ toolAudience, method, request }) {
  return digestValue({
    action_type: "tool.call",
    method,
    request,
    tool_audience: toolAudience
  });
}

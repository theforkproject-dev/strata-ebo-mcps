function assertSerializable(value, path) {
  if (value === undefined) {
    throw new TypeError(`Cannot canonicalize undefined at ${path}`);
  }

  if (typeof value === "function" || typeof value === "symbol" || typeof value === "bigint") {
    throw new TypeError(`Cannot canonicalize ${typeof value} at ${path}`);
  }

  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new TypeError(`Cannot canonicalize non-finite number at ${path}`);
  }
}

export function canonicalize(value, path = "$") {
  assertSerializable(value, path);

  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item, index) => canonicalize(item, `${path}[${index}]`)).join(",")}]`;
  }

  const keys = Object.keys(value).sort();
  const pairs = keys.map((key) => {
    const child = value[key];
    assertSerializable(child, `${path}.${key}`);
    return `${JSON.stringify(key)}:${canonicalize(child, `${path}.${key}`)}`;
  });

  return `{${pairs.join(",")}}`;
}

export function canonicalJsonBytes(value) {
  return Buffer.from(canonicalize(value), "utf8");
}

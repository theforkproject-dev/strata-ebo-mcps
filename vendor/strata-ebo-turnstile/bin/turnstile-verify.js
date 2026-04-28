#!/usr/bin/env node
import { readFileSync } from "node:fs";
import {
  JsonlReceiptLog,
  parseTinfoilTargets,
  verifyCheckpoint,
  verifyCheckpointChain,
  verifySession,
  verifyTinfoilTargets
} from "../src/index.js";

const args = parseArgs(process.argv.slice(2));

if (!args.log || !args.keyring) {
  fatal("Usage: node bin/turnstile-verify.js --log receipts.jsonl --keyring keyring.json [--checkpoint checkpoint.json] [--transparency-log transparency.jsonl] [--now ISO] [--strict true] [--tinfoil-target name=https://host,owner/repo[,/v1/keyring]]");
}

const strict = args.strict === "true" || args.strict === "1";
const keyring = JSON.parse(readFileSync(args.keyring, "utf8"));
const receipts = new JsonlReceiptLog(args.log).readAll();
const transparencyLogEntries = args["transparency-log"] ? new JsonlReceiptLog(args["transparency-log"]).readAll() : undefined;
const priorSessionSummaries = args["prior-summary"] ? JSON.parse(readFileSync(args["prior-summary"], "utf8")) : undefined;
const admissionManifest = receipts[0]?.body?.admission_manifest ?? null;
const session = verifySession(receipts, keyring, {
  now: args.now,
  transparencyLogEntries,
  priorSessionSummaries,
  requireAdmissionManifest: strict,
  requireSideEffectQuorum: strict,
  requireBoundaryQuorum: strict,
  requireTransparencyLog: strict,
  requireCrossSessionSummaries: strict,
  requireStampedOutputTransparency: strict
});

let checkpoint = null;
let checkpoints = null;
if (args.checkpoints) {
  checkpoints = verifyCheckpointChain(JSON.parse(readFileSync(args.checkpoints, "utf8")), receipts, keyring, {
    transparencyLogEntries,
    requireCheckpointQuorum: strict,
    requireCheckpointTransparency: strict
  });
}
if (args.checkpoint) {
  checkpoint = verifyCheckpoint(JSON.parse(readFileSync(args.checkpoint, "utf8")), receipts, keyring, {
    transparencyLogEntries,
    requireCheckpointQuorum: strict,
    requireCheckpointTransparency: strict
  });
}

const tinfoilTargets = parseTinfoilTargets(asArray(args["tinfoil-target"]), asArray(args["tinfoil-config"]));
const tinfoil = await verifyTinfoilTargets({
  targets: tinfoilTargets,
  keyring,
  admissionManifest,
  require: truthy(args["require-tinfoil-attestation"]),
  requireConfigPolicy: truthy(args["require-tinfoil-config-policy"])
});

const ok = session.ok && (!checkpoint || checkpoint.ok) && (!checkpoints || checkpoints.ok) && tinfoil.ok;
console.log(JSON.stringify({ ok, session, checkpoint, checkpoints, tinfoil }, null, 2));
process.exitCode = ok ? 0 : 1;

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) {
      continue;
    }
    const key = item.slice(2);
    const value = argv[index + 1];
    if (parsed[key] === undefined) {
      parsed[key] = value;
    } else if (Array.isArray(parsed[key])) {
      parsed[key].push(value);
    } else {
      parsed[key] = [parsed[key], value];
    }
    index += 1;
  }
  return parsed;
}

function asArray(value) {
  if (value === undefined) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

function truthy(value) {
  return value === "true" || value === "1" || value === true;
}

function fatal(message) {
  console.error(message);
  process.exit(2);
}

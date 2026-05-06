#!/usr/bin/env node
import { renderMarkdownReport, verifyCertificateBundleUrl } from "../src/verify/certificate-verifier.js";

const args = process.argv.slice(2);
const bundleUrl = args.find((arg) => !arg.startsWith("--"));
const formatArg = args.find((arg) => arg.startsWith("--format="));
const format = formatArg ? formatArg.slice("--format=".length) : "json";

if (!bundleUrl) {
  console.error("Usage: node bin/verify-certificate-url.js <bundle-url> [--format=json|markdown]");
  process.exit(2);
}

try {
  const report = await verifyCertificateBundleUrl(bundleUrl);
  if (format === "markdown") {
    console.log(renderMarkdownReport(report));
  } else {
    console.log(JSON.stringify(report, null, 2));
  }
  process.exit(report.ok ? 0 : 1);
} catch (error) {
  const report = { ok: false, error: error.message };
  if (format === "markdown") {
    console.log(`# Strata Certificate Verification: INVALID\n\n${error.message}\n`);
  } else {
    console.error(JSON.stringify(report, null, 2));
  }
  process.exit(1);
}

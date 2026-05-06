import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";

export function createDurableBundleLocation(config, { runId, certificateDigest, uploadedAt = new Date().toISOString() }) {
  if (config.certificateBundle?.backend !== "s3-cloudfront") {
    return null;
  }
  const prefix = trimSlash(config.certificateBundle.s3Prefix || "certificates");
  const publicBase = trimSlash(config.certificateBundle.publicBaseUrl || "");
  if (!config.certificateBundle.s3Bucket || !publicBase) {
    throw new Error("CERTIFICATE_BUNDLE_S3_BUCKET and CERTIFICATE_BUNDLE_PUBLIC_BASE are required for s3-cloudfront bundle publication");
  }
  const keyWithoutPrefix = `email/${runId}/${certificateDigest}/bundle.json`;
  const key = `${prefix}/${keyWithoutPrefix}`;
  return {
    version: "strata.certificate_bundle_publication.v1",
    backend: "s3-cloudfront",
    scope: "complete_bundle_only",
    bucket: config.certificateBundle.s3Bucket,
    key,
    bundle_url: `${publicBase}/${keyWithoutPrefix}`,
    uploaded_at: uploadedAt,
    retention_mode: config.certificateBundle.lockMode || null,
    no_overwrite: true,
    note: "Use this durable bundle URL for long-term verification. Per-artifact URLs in certificate.artifacts are gateway-local debug references."
  };
}

export async function publishCertificateBundle(config, { runId, certificateDigest, bundle, durablePublication }) {
  if (config.certificateBundle?.backend !== "s3-cloudfront") {
    return null;
  }
  const location = durablePublication || createDurableBundleLocation(config, { runId, certificateDigest });
  const client = new S3Client({
    region: config.certificateBundle.awsRegion || config.awsRegion || process.env.AWS_REGION || "us-east-2",
    credentials: config.certificateBundle.awsAccessKeyId && config.certificateBundle.awsSecretAccessKey ? {
      accessKeyId: config.certificateBundle.awsAccessKeyId,
      secretAccessKey: config.certificateBundle.awsSecretAccessKey
    } : undefined
  });
  const body = `${JSON.stringify(bundle, null, 2)}\n`;
  try {
    const result = await client.send(new PutObjectCommand({
      Bucket: location.bucket,
      Key: location.key,
      Body: body,
      ContentType: "application/json; charset=utf-8",
      CacheControl: "public, max-age=31536000, immutable",
      IfNoneMatch: "*",
      Metadata: {
        "run-id": runId,
        "certificate-digest": certificateDigest,
        "strata-version": bundle.version
      }
    }));
    return {
      ...location,
      status: "published",
      etag: result.ETag || null,
      version_id: result.VersionId || null
    };
  } catch (error) {
    if (config.certificateBundle.publishRequired) {
      throw new Error(`durable certificate bundle publication failed: ${error.message}`);
    }
    return {
      ...location,
      status: "error",
      error: error.message
    };
  }
}

function trimSlash(value) {
  return String(value || "").replace(/^\/+|\/+$/g, "");
}

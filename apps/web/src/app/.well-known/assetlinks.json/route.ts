/**
 * Digital Asset Links: proves to Android that this site and the Qalaa Android
 * app belong together, so the app can show the site full-screen without a URL
 * bar. Set SENTINEL_ANDROID_PACKAGE and SENTINEL_ANDROID_CERT_SHA256 (the signing
 * certificate fingerprint, several comma-separated if needed).
 */
export const dynamic = "force-dynamic";

export function GET() {
  const packageName = process.env.SENTINEL_ANDROID_PACKAGE;
  const fingerprints = (process.env.SENTINEL_ANDROID_CERT_SHA256 ?? "")
    .split(",")
    .map((value) => value.trim().toUpperCase())
    .filter((value) => /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(value));
  if (!packageName || !fingerprints.length) return new Response("Not found", { status: 404 });
  return Response.json([
    {
      relation: ["delegate_permission/common.handle_all_urls"],
      target: { namespace: "android_app", package_name: packageName, sha256_cert_fingerprints: fingerprints },
    },
  ]);
}

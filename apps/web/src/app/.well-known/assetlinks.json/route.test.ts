import { afterEach, describe, expect, it, vi } from "vitest";

import { GET } from "./route";

const FINGERPRINT = Array.from({ length: 32 }, () => "AB").join(":");

describe("assetlinks.json", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("is absent until the Android app is configured", async () => {
    expect(GET().status).toBe(404);
  });

  it("lists the package and valid fingerprints only", async () => {
    vi.stubEnv("SENTINEL_ANDROID_PACKAGE", "app.example.sentinel");
    vi.stubEnv("SENTINEL_ANDROID_CERT_SHA256", `${FINGERPRINT.toLowerCase()}, not-a-fingerprint`);
    const body = await GET().json();
    expect(body[0].target).toEqual({ namespace: "android_app", package_name: "app.example.sentinel", sha256_cert_fingerprints: [FINGERPRINT] });
  });
});

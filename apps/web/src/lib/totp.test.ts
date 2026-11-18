import { describe, expect, it } from "vitest";

import { base32Decode, parseOtpauth, secondsRemaining, totpCode } from "./totp";

// RFC 6238 test secret "12345678901234567890" in base32.
const RFC_SECRET_SHA1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
// SHA-256 seed "12345678901234567890123456789012".
const RFC_SECRET_SHA256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";

describe("base32", () => {
  it("decodes known values and ignores spacing/case", () => {
    // RFC 4648: base32("Hello") = "JBSWY3DP".
    expect(new TextDecoder().decode(base32Decode("JBSWY3DP"))).toBe("Hello");
    expect(new TextDecoder().decode(base32Decode("jbswy3dp"))).toBe("Hello");
    expect(base32Decode("gezd gnbv").length).toBeGreaterThan(0);
    expect(() => base32Decode("0189!")).toThrow();
  });
});

describe("RFC 6238 vectors", () => {
  const cfg = (secret: string, algorithm: "SHA-1" | "SHA-256") => ({ secret, algorithm, digits: 8, period: 30, issuer: null, account: null });

  it("matches the published SHA-1 codes", async () => {
    expect(await totpCode(cfg(RFC_SECRET_SHA1, "SHA-1"), 59_000)).toBe("94287082");
    expect(await totpCode(cfg(RFC_SECRET_SHA1, "SHA-1"), 1_111_111_109_000)).toBe("07081804");
    expect(await totpCode(cfg(RFC_SECRET_SHA1, "SHA-1"), 1_234_567_890_000)).toBe("89005924");
    expect(await totpCode(cfg(RFC_SECRET_SHA1, "SHA-1"), 2_000_000_000_000)).toBe("69279037");
  });

  it("matches a published SHA-256 code", async () => {
    expect(await totpCode(cfg(RFC_SECRET_SHA256, "SHA-256"), 59_000)).toBe("46119246");
  });
});

describe("parseOtpauth", () => {
  it("reads a full otpauth URI", () => {
    const cfg = parseOtpauth("otpauth://totp/Example:alice@site.com?secret=GEZDGNBVGY3TQOJQ&issuer=Example&digits=6&period=30&algorithm=SHA1");
    expect(cfg).not.toBeNull();
    expect(cfg!.issuer).toBe("Example");
    expect(cfg!.account).toBe("alice@site.com");
    expect(cfg!.digits).toBe(6);
    expect(cfg!.algorithm).toBe("SHA-1");
  });

  it("accepts a bare base32 secret", () => {
    const cfg = parseOtpauth("gezd gnbv gy3t qojq");
    expect(cfg).not.toBeNull();
    expect(cfg!.period).toBe(30);
    expect(cfg!.secret).toBe("gezdgnbvgy3tqojq");
  });

  it("rejects HOTP and junk", () => {
    expect(parseOtpauth("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=0")).toBeNull();
    expect(parseOtpauth("")).toBeNull();
    expect(parseOtpauth("!!!not base32!!!")).toBeNull();
    expect(parseOtpauth("otpauth://totp/x")).toBeNull(); // no secret
  });

  it("generates a 6-digit code from a parsed URI", async () => {
    const cfg = parseOtpauth(`otpauth://totp/x?secret=${RFC_SECRET_SHA1}`)!;
    const code = await totpCode(cfg, 59_000);
    expect(code).toMatch(/^\d{6}$/);
    // 6-digit truncation of the RFC 8-digit "94287082".
    expect(code).toBe("287082");
  });
});

describe("countdown", () => {
  it("reports seconds left in the step", () => {
    expect(secondsRemaining({ secret: "A", algorithm: "SHA-1", digits: 6, period: 30, issuer: null, account: null }, 0)).toBe(30);
    expect(secondsRemaining({ secret: "A", algorithm: "SHA-1", digits: 6, period: 30, issuer: null, account: null }, 25_000)).toBe(5);
  });
});

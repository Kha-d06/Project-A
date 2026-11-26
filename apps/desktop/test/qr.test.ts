import { readFileSync } from "node:fs";
import { join } from "node:path";

import jpeg from "jpeg-js";
import { PNG } from "pngjs";
import { describe, expect, it } from "vitest";

import { analyzeLocally, compilePack, verdict } from "../../thunderbird/src/lib/analysis.js";
import { decodeQr, imageKind, imageSize, qrLinks } from "../src/engine/qr";

const fixture = (name: string) => readFileSync(join(__dirname, "fixtures", "qr", name));

describe("QR codes in email images", () => {
  it("decodes a QR code's destination from PNG and JPEG, without opening it", () => {
    expect(decodeQr(fixture("phish.png"))).toBe("https://paypa1-login.example/verify?id=93");
    const png = PNG.sync.read(fixture("ticket.png"));
    const asJpeg = jpeg.encode({ data: png.data, width: png.width, height: png.height }, 95).data;
    expect(imageKind(asJpeg)).toBe("jpeg");
    expect(imageSize(asJpeg)).toEqual({ width: png.width, height: png.height });
    expect(decodeQr(asJpeg)).toBe("https://www.example.org/tickets/123");
  });

  it("keeps only web addresses (a Wi-Fi code is ignored)", () => {
    expect(qrLinks([{ content: fixture("wifi.png") }, { content: fixture("ticket.png") }])).toEqual(["https://www.example.org/tickets/123"]);
  });

  it("refuses oversized, corrupt and unsupported images before decoding", () => {
    // A valid PNG signature and header claiming 50,000 × 50,000 pixels: skipped by the size check.
    const bomb = Buffer.from(fixture("ticket.png"));
    bomb.writeUInt32BE(50_000, 16);
    bomb.writeUInt32BE(50_000, 20);
    expect(imageSize(bomb)).toEqual({ width: 50_000, height: 50_000 });
    expect(decodeQr(bomb)).toBeNull();
    // Truncated and random data with an image signature.
    expect(decodeQr(fixture("phish.png").subarray(0, 60))).toBeNull();
    expect(decodeQr(Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(200, 7)]))).toBeNull();
    // Not an image at all (a GIF and a PDF are not decoded).
    expect(decodeQr(Buffer.from("GIF89a....."))).toBeNull();
    expect(decodeQr(Buffer.from("%PDF-1.7\n"))).toBeNull();
  });

  it("a QR code to a look-alike site, in a sign-in email, is a phishing warning", () => {
    const urlRules = JSON.parse(readFileSync(join(__dirname, "../../../services/api/app/rules/url_rules.json"), "utf8"));
    const brands = Object.fromEntries(Object.entries(urlRules.brands as Record<string, { name: string; domains: string[] }>).map(([k, v]) => [k, v]));
    const pack = compilePack({ version: "t", rules: [], brands, shorteners: [], url_rules: urlRules });
    const email = {
      from_header: "PayPal <service@paypa1-login.example>",
      reply_to: null,
      subject: "Verify your account",
      authentication_results: "",
      text: "Scan the code with your phone to verify your account.",
      links: [],
      qr_links: qrLinks([{ content: fixture("phish.png") }]),
    };
    const findings = analyzeLocally(email, pack, "en");
    const categories = findings.map((f) => `${f.severity}:${f.category}`);
    expect(categories).toEqual(expect.arrayContaining(["low:qr_code", "medium:qr_phishing", "medium:lookalike_link"]));
    expect(verdict(findings).risk).toBe("suspicious");

    // A ticket QR from an ordinary sender: noted, not a warning.
    const ticket = analyzeLocally({ ...email, from_header: "Events <tickets@example.org>", subject: "Your ticket", text: "See you there!", qr_links: qrLinks([{ content: fixture("ticket.png") }]) }, pack, "en");
    expect(ticket.map((f) => `${f.severity}:${f.category}`)).toEqual(["low:qr_code"]);
    expect(verdict(ticket).risk).toBe("no_known_threat");
  });
});

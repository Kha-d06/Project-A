import { randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";

import { RansomwareDetector, entropy } from "../src/engine/ransomware";
import { parseApt, parseNetsh, parseNmcli, parseSoftwareUpdate, parseSystemProfiler, parseWinget } from "../src/engine/system";

describe("Wi-Fi security", () => {
  it("reads nmcli", () => {
    expect(parseNmcli("no:Neighbour:WPA2\nyes:Cafe Free:\n")).toEqual({ ssid: "Cafe Free", security: "", risk: "open" });
    expect(parseNmcli("yes:Home\\:5G:WPA2 WPA3\n").risk).toBe("ok");
    expect(parseNmcli("yes:Old:WEP\n").risk).toBe("weak");
    expect(parseNmcli("no:Other:WPA2\n").risk).toBe("none");
  });

  it("reads netsh", () => {
    const out = "    Name                   : Wi-Fi\n    State                  : connected\n    SSID                   : Airport_Free\n    Authentication         : Open\n";
    expect(parseNetsh(out)).toEqual({ ssid: "Airport_Free", security: "Open", risk: "open" });
    expect(parseNetsh(out.replace("Open", "WPA2-Personal")).risk).toBe("ok");
    expect(parseNetsh("    State                  : disconnected\n").risk).toBe("none");
  });

  it("reads system_profiler", () => {
    const out = "Wi-Fi:\n  Interfaces:\n    en0:\n      Current Network Information:\n        HotelWiFi:\n          PHY Mode: 802.11ac\n          Security: None\n      Other Local Wi-Fi Networks:\n";
    expect(parseSystemProfiler(out)).toEqual({ ssid: "HotelWiFi", security: "None", risk: "open" });
  });
});

describe("software updates", () => {
  it("parses winget, softwareupdate and apt", () => {
    const winget = [
      "Name               Id                    Version     Available   Source",
      "------------------------------------------------------------------------",
      "Mozilla Firefox    Mozilla.Firefox       119.0       120.0.1     winget",
      "7-Zip              7zip.7zip             22.01       23.01       winget",
      "2 upgrades available.",
    ].join("\n");
    expect(parseWinget(winget)).toEqual([
      { name: "Mozilla Firefox", current: "119.0", available: "120.0.1" },
      { name: "7-Zip", current: "22.01", available: "23.01" },
    ]);
    expect(parseSoftwareUpdate("Software Update found the following:\n* Label: macOS Sequoia 15.2-24C101\n\tTitle: macOS\n")).toEqual([
      { name: "macOS Sequoia 15.2-24C101", current: null, available: null },
    ]);
    expect(parseApt("Listing...\nopenssl/jammy-updates 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.15]\n")).toEqual([
      { name: "openssl", available: "3.0.2-0ubuntu1.18", current: "3.0.2-0ubuntu1.15" },
    ]);
  });
});

describe("ransomware watch", () => {
  it("measures entropy", () => {
    expect(entropy(Buffer.alloc(1000, 65))).toBe(0);
    expect(entropy(randomBytes(65536))).toBeGreaterThan(7.9);
  });

  it("alerts on mass renames with a ransom note, once", () => {
    const detector = new RansomwareDetector();
    let alert = null;
    for (let i = 0; i < 8; i += 1) alert = detector.feed({ path: `/docs/report${i}.docx.lockbit`, at: 1000 + i });
    expect(alert?.reasons[0]).toContain("8 files renamed");
    expect(detector.feed({ path: "/docs/README_DECRYPT.txt", at: 2000 })).toBeNull(); // cooldown
  });

  it("alerts on many documents becoming random, but not on photos", () => {
    const photos = new RansomwareDetector();
    for (let i = 0; i < 40; i += 1) expect(photos.feed({ path: `/pics/img${i}.jpg`, at: i, entropy: 7.95 })).toBeNull();
    const documents = new RansomwareDetector();
    let alert = null;
    for (let i = 0; i < 25; i += 1) alert = documents.feed({ path: `/docs/notes${i}.txt`, at: i * 100, entropy: 7.97 });
    expect(alert?.reasons[0]).toContain("25 documents rewritten");
  });

  it("ignores ordinary editing", () => {
    const detector = new RansomwareDetector();
    for (let i = 0; i < 100; i += 1) expect(detector.feed({ path: `/docs/draft${i % 3}.txt`, at: i * 50, entropy: 4.5 })).toBeNull();
  });
});

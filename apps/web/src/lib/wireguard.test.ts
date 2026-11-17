import { describe, expect, it } from "vitest";

import { buildConfig, generateKeyPair, qrModules, tunnelFileName } from "./wireguard";

const PKCS8_X25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
const bytes = (b64: string) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

async function importPrivate(b64: string) {
  const der = new Uint8Array(48);
  der.set(PKCS8_X25519);
  der.set(bytes(b64), 16);
  return crypto.subtle.importKey("pkcs8", der, { name: "X25519" }, false, ["deriveBits"]);
}
const importPublic = (b64: string) => crypto.subtle.importKey("raw", bytes(b64), { name: "X25519" }, false, []);

describe("WireGuard keys", () => {
  it("are 32-byte standard base64, as wg expects", async () => {
    const pair = await generateKeyPair();
    for (const key of [pair.privateKey, pair.publicKey]) {
      expect(key).toMatch(/^[A-Za-z0-9+/]{43}=$/);
      expect(bytes(key)).toHaveLength(32);
    }
  });

  it("form a real key pair: both sides agree on the shared secret", async () => {
    const a = await generateKeyPair();
    const b = await generateKeyPair();
    const ab = await crypto.subtle.deriveBits({ name: "X25519", public: await importPublic(b.publicKey) }, await importPrivate(a.privateKey), 256);
    const ba = await crypto.subtle.deriveBits({ name: "X25519", public: await importPublic(a.publicKey) }, await importPrivate(b.privateKey), 256);
    expect(new Uint8Array(ab)).toEqual(new Uint8Array(ba));
  });
});

describe("WireGuard configuration", () => {
  it("routes everything through the tunnel", () => {
    const text = buildConfig({ privateKey: "P", address: "10.13.13.2/32", dns: "1.1.1.1", serverPublicKey: "S", endpoint: "vpn.example.org:51820", allowedIps: "0.0.0.0/0, ::/0" });
    expect(text).toContain("[Interface]\nPrivateKey = P\nAddress = 10.13.13.2/32\nDNS = 1.1.1.1\n");
    expect(text).toContain("AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25");
  });

  it("names files the way WireGuard apps accept", () => {
    expect(tunnelFileName("Sara's iPhone 15")).toBe("sntl-sara-s-iph.conf");
    expect(tunnelFileName("هاتفي")).toBe("sntl-vpn.conf");
    expect(tunnelFileName("Laptop")).toBe("sntl-laptop.conf");
  });

  it("encodes a QR code big enough for a config", () => {
    const modules = qrModules("x".repeat(300));
    expect(modules.length).toBeGreaterThan(40);
    expect(modules.every((row) => row.length === modules.length)).toBe(true);
  });
});

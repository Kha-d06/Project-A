import { describe, expect, it } from "vitest";

import { generateSharingKeys, keyFingerprint, openSealed, pinStatus, sealTo } from "./vault-sharing";

describe("vault sharing crypto", () => {
  it("seals to a recipient and only they can open it", async () => {
    const recipient = await generateSharingKeys();
    const other = await generateSharingKeys();
    const sealed = await sealTo(recipient.publicKey, "super-secret-login");

    expect(await openSealed(recipient.privateKey, sealed)).toBe("super-secret-login");
    // Someone else's key cannot read it.
    await expect(openSealed(other.privateKey, sealed)).rejects.toBeTruthy();
  });

  it("uses a fresh ephemeral key each time (different ciphertext for the same input)", async () => {
    const recipient = await generateSharingKeys();
    const a = await sealTo(recipient.publicKey, "same");
    const b = await sealTo(recipient.publicKey, "same");
    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.ephemeral).not.toBe(b.ephemeral);
    expect(await openSealed(recipient.privateKey, a)).toBe("same");
    expect(await openSealed(recipient.privateKey, b)).toBe("same");
  });

  it("round-trips a larger JSON payload (an emergency vault key)", async () => {
    const recipient = await generateSharingKeys();
    const payload = JSON.stringify({ wrappedKey: "x".repeat(200), note: "emergency" });
    const sealed = await sealTo(recipient.publicKey, payload);
    expect(JSON.parse(await openSealed(recipient.privateKey, sealed)).note).toBe("emergency");
  });
});

describe("sharing key fingerprints", () => {
  it("are stable per key, differ between keys, and read as 8 groups of 4", async () => {
    const a = await generateSharingKeys();
    const b = await generateSharingKeys();
    const fa = await keyFingerprint(a.publicKey);
    expect(fa).toMatch(/^([0-9a-f]{4} ){7}[0-9a-f]{4}$/);
    expect(await keyFingerprint(a.publicKey)).toBe(fa);
    expect(await keyFingerprint(b.publicKey)).not.toBe(fa);
  });

  it("flag a recipient whose key changed since it was remembered", () => {
    const pinned = { u1: "aaaa bbbb" };
    expect(pinStatus(undefined, "u1", "aaaa bbbb")).toBe("new");
    expect(pinStatus(pinned, "u2", "cccc")).toBe("new");
    expect(pinStatus(pinned, "u1", "aaaa bbbb")).toBe("same");
    expect(pinStatus(pinned, "u1", "dddd eeee")).toBe("changed");
  });
});


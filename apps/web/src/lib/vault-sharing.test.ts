import { describe, expect, it } from "vitest";

import { generateSharingKeys, openSealed, sealTo } from "./vault-sharing";

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

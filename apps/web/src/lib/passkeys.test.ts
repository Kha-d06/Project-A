import { creationOptions, credentialJson, fromBase64url, requestOptions, toBase64url } from "./passkeys";

describe("passkey helpers", () => {
  it("round-trips base64url without padding", () => {
    const bytes = new Uint8Array([0, 251, 255, 62, 63, 1, 2]);
    const text = toBase64url(bytes);
    expect(text).not.toMatch(/[+/=]/);
    expect([...fromBase64url(text)]).toEqual([...bytes]);
  });

  it("turns server options into what the browser wants", () => {
    const create = creationOptions({
      challenge: toBase64url(new Uint8Array([1, 2, 3])),
      user: { id: toBase64url(new Uint8Array([9])), name: "a@example.com", displayName: "a" },
      rp: { id: "localhost", name: "Qalaa" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: [{ id: toBase64url(new Uint8Array([7, 7])), type: "public-key" }],
    });
    expect([...new Uint8Array(create.challenge as ArrayBuffer)]).toEqual([1, 2, 3]);
    expect([...new Uint8Array(create.user.id as ArrayBuffer)]).toEqual([9]);
    expect([...new Uint8Array(create.excludeCredentials![0]!.id as ArrayBuffer)]).toEqual([7, 7]);
    const get = requestOptions({ challenge: toBase64url(new Uint8Array([5])), rpId: "localhost" });
    expect(get.allowCredentials).toEqual([]);
  });

  it("turns an assertion into JSON the server verifies", () => {
    const buf = (n: number[]) => new Uint8Array(n).buffer;
    const assertion = {
      id: "AQI",
      rawId: buf([1, 2]),
      type: "public-key",
      getClientExtensionResults: () => ({}),
      response: { clientDataJSON: buf([3]), authenticatorData: buf([4]), signature: buf([5]), userHandle: buf([6]) },
    } as unknown as PublicKeyCredential;
    expect(credentialJson(assertion)).toEqual({
      id: "AQI",
      rawId: "AQI",
      type: "public-key",
      clientExtensionResults: {},
      response: { clientDataJSON: "Aw", authenticatorData: "BA", signature: "BQ", userHandle: "Bg" },
    });
  });
});

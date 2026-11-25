/**
 * Passkeys in the browser: the server sends WebAuthn options as JSON
 * (base64url strings), navigator.credentials wants ArrayBuffers, and the
 * result goes back as JSON. Only the public key and signatures ever leave the
 * device; the private key stays in the authenticator.
 */

export function toBase64url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let text = "";
  for (const b of bytes) text += String.fromCharCode(b);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64url(text: string): Uint8Array<ArrayBuffer> {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const raw = atob(padded);
  const out = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

import { useSyncExternalStore } from "react";

type Json = Record<string, unknown>;

const noSubscription = () => () => {};

/** Whether this browser can use passkeys; false while rendering on the server. */
export function usePasskeysSupported(): boolean {
  return useSyncExternalStore(noSubscription, passkeysSupported, () => false);
}

export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function" && !!navigator.credentials;
}

export function creationOptions(json: Json): PublicKeyCredentialCreationOptions {
  const user = json.user as { id: string; name: string; displayName: string };
  return {
    ...(json as unknown as PublicKeyCredentialCreationOptions),
    challenge: fromBase64url(json.challenge as string),
    user: { ...user, id: fromBase64url(user.id) },
    excludeCredentials: ((json.excludeCredentials as { id: string; type: "public-key"; transports?: AuthenticatorTransport[] }[]) ?? []).map((c) => ({ ...c, id: fromBase64url(c.id) })),
  };
}

export function requestOptions(json: Json): PublicKeyCredentialRequestOptions {
  return {
    ...(json as unknown as PublicKeyCredentialRequestOptions),
    challenge: fromBase64url(json.challenge as string),
    allowCredentials: ((json.allowCredentials as { id: string; type: "public-key" }[]) ?? []).map((c) => ({ ...c, id: fromBase64url(c.id) })),
  };
}

/** A PublicKeyCredential from create() or get(), as the JSON the server verifies. */
export function credentialJson(credential: PublicKeyCredential): Json {
  const response = credential.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  const out: Json = {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults?.() ?? {},
  };
  if ("attestationObject" in response && response.attestationObject) {
    out.response = {
      clientDataJSON: toBase64url(response.clientDataJSON),
      attestationObject: toBase64url(response.attestationObject),
      transports: typeof response.getTransports === "function" ? response.getTransports() : [],
    };
  } else {
    out.response = {
      clientDataJSON: toBase64url(response.clientDataJSON),
      authenticatorData: toBase64url(response.authenticatorData),
      signature: toBase64url(response.signature),
      userHandle: response.userHandle ? toBase64url(response.userHandle) : null,
    };
  }
  return out;
}

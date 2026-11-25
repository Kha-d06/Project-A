/**
 * Browser fingerprint noise: small, consistent changes to the values that
 * fingerprinting scripts read, so the same browser looks different on each
 * site and in each browser session, while each site sees stable values within
 * a session (reading twice gives the same answer, so the noise can't be spotted
 * by comparing reads).
 *
 * - Canvas toDataURL, toBlob and getImageData: a few pixels change by one
 *   colour step, chosen by the seed (invisible to people).
 * - WebGL: the unmasked GPU vendor and renderer come from a short list of
 *   common values instead of the real ones.
 * - Audio: AudioBuffer.getChannelData gets a tiny, inaudible offset on a few samples.
 * - navigator.hardwareConcurrency and deviceMemory report common values.
 *
 * The seed is an HMAC of the site's origin with a secret that lives only for
 * the browser session, computed in the extension's background. It is handed to
 * `installNoise` as an argument when the script is injected, so the page has no
 * way to read it. Injection happens as the page starts loading; a script that
 * runs before it (rare) sees the real values. A site can be excluded.
 */

/** Derives a site's seed from the session secret. */
export async function originSeed(secret: Uint8Array, origin: string): Promise<number> {
  const key = await crypto.subtle.importKey("raw", secret as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(origin)));
  return ((mac[0]! << 24) | (mac[1]! << 16) | (mac[2]! << 8) | mac[3]!) >>> 0;
}

export function isBypassed(host: string, bypass: readonly string[]): boolean {
  const h = host.toLowerCase();
  return bypass.some((d) => h === d || h.endsWith(`.${d}`));
}

/**
 * Installs the noise in the current page. Self-contained (no imports or outer
 * variables): it is passed to chrome.scripting.executeScript as a function.
 */
export function installNoise(seed: number): void {
  const g = globalThis as typeof globalThis & { __qalaaNoise?: boolean };
  // Once per document, and never twice (frames, repeated injection).
  if (Object.getOwnPropertyDescriptor(g, "__qalaaNoise")) return;
  Object.defineProperty(g, "__qalaaNoise", { value: true, enumerable: false });

  /** A small deterministic hash of (seed, n): mulberry32-style mixing. */
  const mix = (n: number) => {
    let t = (seed ^ Math.imul(n | 0, 0x9e3779b1)) >>> 0;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };

  const native = new WeakSet<object>();
  /** Keeps a replaced function looking like the original to toString checks. */
  const disguise = <T extends object>(replacement: T, original: object): T => {
    native.add(replacement);
    nativeNames.set(replacement, (original as { name?: string }).name ?? "");
    return replacement;
  };
  const nativeNames = new WeakMap<object, string>();
  const toString = Function.prototype.toString;
  const patchedToString = function (this: unknown) {
    if (typeof this === "function" && native.has(this)) return `function ${nativeNames.get(this)}() { [native code] }`;
    return toString.call(this as () => void);
  };
  native.add(patchedToString);
  nativeNames.set(patchedToString, "toString");
  Function.prototype.toString = patchedToString;

  // --- Canvas --------------------------------------------------------------------
  const noisePixels = (data: Uint8ClampedArray) => {
    for (let i = 0; i < data.length; i += 4) {
      // About one pixel in 64 changes by one step in one colour channel.
      const r = mix(i >> 2);
      if (r < 1 / 64) {
        const channel = i + Math.floor(mix((i >> 2) + 7919) * 3);
        const v = data[channel]!;
        data[channel] = v === 255 ? 254 : v === 0 ? 1 : v + (r < 1 / 128 ? 1 : -1);
      }
    }
  };
  const ctxProto = g.CanvasRenderingContext2D?.prototype;
  const getImageData = ctxProto?.getImageData;
  if (ctxProto && getImageData) {
    ctxProto.getImageData = disguise(function (this: CanvasRenderingContext2D, ...args: Parameters<typeof getImageData>) {
      const image = getImageData.apply(this, args);
      noisePixels(image.data);
      return image;
    }, getImageData);
  }
  const canvasProto = g.HTMLCanvasElement?.prototype;
  /** A copy of the canvas with noise, for exports; the page's own canvas is untouched. */
  const noisyCopy = (canvas: HTMLCanvasElement): HTMLCanvasElement | null => {
    if (!getImageData || !canvas.width || !canvas.height) return null;
    const copy = document.createElement("canvas");
    copy.width = canvas.width;
    copy.height = canvas.height;
    const ctx = copy.getContext("2d");
    if (!ctx) return null;
    try {
      ctx.drawImage(canvas, 0, 0);
      const image = getImageData.call(ctx, 0, 0, copy.width, copy.height);
      noisePixels(image.data);
      ctx.putImageData(image, 0, 0);
      return copy;
    } catch {
      return null; // a tainted or WebGL-only canvas: leave it
    }
  };
  const toDataURL = canvasProto?.toDataURL;
  if (canvasProto && toDataURL) {
    canvasProto.toDataURL = disguise(function (this: HTMLCanvasElement, ...args: Parameters<typeof toDataURL>) {
      return toDataURL.apply(noisyCopy(this) ?? this, args);
    }, toDataURL);
  }
  const toBlob = canvasProto?.toBlob;
  if (canvasProto && toBlob) {
    canvasProto.toBlob = disguise(function (this: HTMLCanvasElement, ...args: Parameters<typeof toBlob>) {
      return toBlob.apply(noisyCopy(this) ?? this, args);
    }, toBlob);
  }

  // --- WebGL ---------------------------------------------------------------------
  const VENDORS = ["Google Inc. (Intel)", "Google Inc. (NVIDIA)", "Google Inc. (AMD)"];
  const RENDERERS = [
    "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
  ];
  const pick = Math.floor(mix(101) * VENDORS.length);
  for (const proto of [g.WebGLRenderingContext?.prototype, g.WebGL2RenderingContext?.prototype]) {
    const getParameter = proto?.getParameter;
    if (!proto || !getParameter) continue;
    proto.getParameter = disguise(function (this: WebGLRenderingContext, name: number) {
      if (name === 0x9245) return VENDORS[pick]; // UNMASKED_VENDOR_WEBGL
      if (name === 0x9246) return RENDERERS[pick]; // UNMASKED_RENDERER_WEBGL
      return getParameter.call(this, name);
    }, getParameter);
  }

  // --- Audio ---------------------------------------------------------------------
  const audioProto = g.AudioBuffer?.prototype;
  const getChannelData = audioProto?.getChannelData;
  if (audioProto && getChannelData) {
    const done = new WeakMap<AudioBuffer, Set<number>>();
    audioProto.getChannelData = disguise(function (this: AudioBuffer, channel: number) {
      const data = getChannelData.call(this, channel);
      // Same array every call, so the offset is applied once per channel.
      const seen = done.get(this) ?? new Set<number>();
      if (!seen.has(channel)) {
        seen.add(channel);
        done.set(this, seen);
        for (let i = 0; i < data.length; i += 97) if (mix(i + channel * 31) < 0.5) data[i] = data[i]! + 1e-7;
      }
      return data;
    }, getChannelData);
  }

  // --- Navigator -----------------------------------------------------------------
  const navProto = g.Navigator?.prototype;
  const defineGetter = (name: "hardwareConcurrency" | "deviceMemory", values: number[]) => {
    const original = navProto && Object.getOwnPropertyDescriptor(navProto, name);
    if (!navProto || !original?.get) return;
    const value = values[Math.floor(mix(name.length * 1009) * values.length)];
    Object.defineProperty(navProto, name, { ...original, get: disguise(function hardware() { return value; }, original.get) });
  };
  defineGetter("hardwareConcurrency", [4, 8, 12]);
  defineGetter("deviceMemory", [4, 8]);
}

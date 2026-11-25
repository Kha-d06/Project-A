/**
 * Browser fingerprint noise: small, consistent changes to the values that
 * fingerprinting scripts read, so the same browser looks different on each
 * site and in each browser session, while each site sees stable values within
 * a session (reading twice gives the same answer, so the noise can't be spotted
 * by comparing reads).
 *
 * - Canvas: toDataURL, toBlob, getImageData, OffscreenCanvas convertToBlob and
 *   its getImageData: a few pixels change by one colour step.
 * - WebGL: the unmasked GPU vendor and renderer come from a short list of
 *   common values; readPixels gets the same pixel noise as canvas.
 * - Audio: AudioBuffer getChannelData and copyFromChannel, and AnalyserNode's
 *   float readings, get tiny, inaudible offsets.
 * - navigator.hardwareConcurrency and deviceMemory report common values.
 *
 * Covered realms: the page, same-origin frames a script creates (about:blank,
 * srcdoc: patched when the page reaches into them or inserts them), popups
 * opened with window.open, and dedicated and shared workers (started through a
 * small wrapper that installs the noise first; if the site's security policy
 * forbids that, the worker starts unprotected rather than breaking).
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
 * Installs the noise in the current realm and every same-origin realm it
 * creates. Self-contained (no imports or outer variables): it is passed to
 * chrome.scripting.executeScript as a function, and its own source is reused
 * to start workers.
 */
export function installNoise(seed: number): void {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  type Realm = any;
  const self = installNoise;
  const FLAG = "__qalaaNoise";

  /** A small deterministic hash of (seed, n): mulberry32-style mixing. */
  const mix = (n: number) => {
    let t = (seed ^ Math.imul(n | 0, 0x9e3779b1)) >>> 0;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };

  // One registry for every realm, so each realm's Function.prototype.toString
  // recognises replacements wherever they were made.
  const native = new WeakMap<object, string>();
  const disguise = <T extends object>(replacement: T, original: object): T => {
    native.set(replacement, (original as { name?: string }).name ?? "");
    return replacement;
  };

  const noisePixels = (data: Uint8Array | Uint8ClampedArray) => {
    for (let i = 0; i + 3 < data.length; i += 4) {
      // About one pixel in 64 changes by one step in one colour channel.
      const r = mix(i >> 2);
      if (r < 1 / 64) {
        const channel = i + Math.floor(mix((i >> 2) + 7919) * 3);
        const v = data[channel]!;
        data[channel] = v === 255 ? 254 : v === 0 ? 1 : v + (r < 1 / 128 ? 1 : -1);
      }
    }
  };
  /** Audio offset at sample `i` of `channel`: applied once per buffer and channel. */
  const audioOffset = (i: number, channel: number) => (i % 97 === 0 && mix(i + channel * 31) < 0.5 ? 1e-7 : 0);

  const patch = (proto: Realm, name: string, make: (original: Realm) => Realm) => {
    const original = proto?.[name];
    if (typeof original !== "function") return;
    proto[name] = disguise(make(original), original);
  };

  const patchRealm = (g: Realm) => {
    try {
      if (!g || Object.getOwnPropertyDescriptor(g, FLAG)) return;
      Object.defineProperty(g, FLAG, { value: true, enumerable: false });
    } catch {
      return; // cross-origin or closed: nothing we can do, and nothing it can leak to this page
    }

    const toString = g.Function.prototype.toString;
    const patchedToString = function (this: unknown) {
      if (typeof this === "function" && native.has(this)) return `function ${native.get(this)}() { [native code] }`;
      return toString.call(this);
    };
    native.set(patchedToString, "toString");
    g.Function.prototype.toString = patchedToString;

    // --- Canvas ------------------------------------------------------------------
    for (const ctx of [g.CanvasRenderingContext2D, g.OffscreenCanvasRenderingContext2D]) {
      patch(ctx?.prototype, "getImageData", (getImageData) =>
        function (this: unknown, ...args: unknown[]) {
          const image = getImageData.apply(this, args);
          noisePixels(image.data);
          return image;
        },
      );
    }
    /** A copy of the canvas with noise, for exports; the page's own canvas is untouched. */
    const noisyCopy = (canvas: Realm): Realm | null => {
      if (!canvas.width || !canvas.height) return null;
      try {
        const copy = g.document ? g.document.createElement("canvas") : new g.OffscreenCanvas(canvas.width, canvas.height);
        copy.width = canvas.width;
        copy.height = canvas.height;
        const ctx = copy.getContext("2d");
        if (!ctx) return null;
        ctx.drawImage(canvas, 0, 0);
        // The patched getImageData adds the noise.
        ctx.putImageData(ctx.getImageData(0, 0, copy.width, copy.height), 0, 0);
        return copy;
      } catch {
        return null; // a tainted canvas: leave it
      }
    };
    for (const name of ["toDataURL", "toBlob"]) {
      patch(g.HTMLCanvasElement?.prototype, name, (original) =>
        function (this: unknown, ...args: unknown[]) {
          return original.apply(noisyCopy(this) ?? this, args);
        },
      );
    }
    patch(g.OffscreenCanvas?.prototype, "convertToBlob", (original) =>
      function (this: unknown, ...args: unknown[]) {
        return original.apply(noisyCopy(this) ?? this, args);
      },
    );

    // --- WebGL -------------------------------------------------------------------
    const VENDORS = ["Google Inc. (Intel)", "Google Inc. (NVIDIA)", "Google Inc. (AMD)"];
    const RENDERERS = [
      "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
      "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)",
      "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
    ];
    const pick = Math.floor(mix(101) * VENDORS.length);
    for (const gl of [g.WebGLRenderingContext, g.WebGL2RenderingContext]) {
      patch(gl?.prototype, "getParameter", (getParameter) =>
        function (this: unknown, name: number) {
          if (name === 0x9245) return VENDORS[pick]; // UNMASKED_VENDOR_WEBGL
          if (name === 0x9246) return RENDERERS[pick]; // UNMASKED_RENDERER_WEBGL
          return getParameter.call(this, name);
        },
      );
      patch(gl?.prototype, "readPixels", (readPixels) =>
        function (this: unknown, ...args: unknown[]) {
          const result = readPixels.apply(this, args);
          const out = args[6];
          if (out instanceof Uint8Array || out instanceof Uint8ClampedArray) noisePixels(out);
          return result;
        },
      );
    }

    // --- Audio -------------------------------------------------------------------
    const audioProto = g.AudioBuffer?.prototype;
    const done = new WeakMap<object, Set<number>>();
    patch(audioProto, "getChannelData", (original) =>
      function (this: Realm, channel: number) {
        const data = original.call(this, channel);
        // Same array every call, and it is the buffer itself: offset it once per channel.
        const seen = done.get(this) ?? new Set<number>();
        if (!seen.has(channel)) {
          seen.add(channel);
          done.set(this, seen);
          for (let i = 0; i < data.length; i += 97) data[i] += audioOffset(i, channel);
        }
        return data;
      },
    );
    patch(audioProto, "copyFromChannel", (original) =>
      function (this: Realm, destination: Float32Array, channel: number, start = 0) {
        const result = original.call(this, destination, channel, start);
        // Already in the buffer if getChannelData ran first; otherwise add it to the copy.
        if (!done.get(this)?.has(channel)) {
          for (let k = 0; k < destination.length; k++) destination[k] = destination[k]! + audioOffset(start + k, channel);
        }
        return result;
      },
    );
    for (const name of ["getFloatFrequencyData", "getFloatTimeDomainData"]) {
      patch(g.AnalyserNode?.prototype, name, (original) =>
        function (this: unknown, array: Float32Array) {
          const result = original.call(this, array);
          for (let i = 0; i < array.length; i += 7) if (mix(i + 4099) < 0.5) array[i] = array[i]! + 1e-4;
          return result;
        },
      );
    }

    // --- Navigator (also WorkerNavigator) ----------------------------------------
    for (const nav of [g.Navigator?.prototype, g.WorkerNavigator?.prototype]) {
      for (const [name, values] of [
        ["hardwareConcurrency", [4, 8, 12]],
        ["deviceMemory", [4, 8]],
      ] as const) {
        const original = nav && Object.getOwnPropertyDescriptor(nav, name);
        if (!original?.get) continue;
        const value = values[Math.floor(mix(name.length * 1009) * values.length)];
        Object.defineProperty(nav, name, { ...original, get: disguise(function () { return value; }, original.get) });
      }
    }

    // --- Same-origin frames and popups -------------------------------------------
    const guardFrame = (frame: Realm) => {
      try {
        if (frame?.contentWindow) patchRealm(frame.contentWindow);
      } catch {
        // cross-origin
      }
    };
    for (const ctor of [g.HTMLIFrameElement, g.HTMLFrameElement, g.HTMLObjectElement]) {
      for (const prop of ["contentWindow", "contentDocument"]) {
        const proto = ctor?.prototype;
        const original = proto && Object.getOwnPropertyDescriptor(proto, prop);
        if (!original?.get) continue;
        Object.defineProperty(proto, prop, {
          ...original,
          get: disguise(function (this: Realm) {
            const value = original.get!.call(this);
            const win = prop === "contentWindow" ? value : value?.defaultView;
            if (win) patchRealm(win);
            return value;
          }, original.get),
        });
      }
    }
    /** After a node is inserted, its frames exist: patch them before the page can reach them through window[i]. */
    const afterInsert = (node: Realm) => {
      if (!node || typeof node !== "object") return;
      if (node.tagName === "IFRAME" || node.tagName === "FRAME") guardFrame(node);
      if (typeof node.querySelectorAll === "function") for (const f of node.querySelectorAll("iframe,frame")) guardFrame(f);
    };
    for (const [proto, names] of [
      [g.Node?.prototype, ["appendChild", "insertBefore", "replaceChild"]],
      [g.Element?.prototype, ["append", "prepend", "after", "before", "replaceWith", "insertAdjacentElement"]],
    ] as const) {
      for (const name of names) {
        patch(proto, name, (original) =>
          function (this: unknown, ...args: unknown[]) {
            const result = original.apply(this, args);
            for (const arg of args) afterInsert(arg);
            return result;
          },
        );
      }
    }
    patch(g, "open", (original) =>
      function (this: unknown, ...args: unknown[]) {
        const win = original.apply(this, args);
        if (win) patchRealm(win);
        return win;
      },
    );

    // --- Workers -----------------------------------------------------------------
    /** Wraps a worker script so the noise is installed before the site's code runs. */
    const wrapWorker = (Original: Realm) => {
      if (typeof Original !== "function" || !g.Blob || !g.URL?.createObjectURL) return;
      const Wrapped = function (this: unknown, url: string | URL, options?: { type?: string }) {
        if (!new.target) return Original(url, options); // let the browser throw its usual error
        try {
          const href = new g.URL(String(url), g.location.href).href;
          if (!href.startsWith("data:")) {
            const boot =
              options?.type === "module"
                ? `(${self.toString()})(${seed});\nawait import(${JSON.stringify(href)});`
                : `(${self.toString()})(${seed});\n` +
                  // Relative imports and requests keep resolving against the real script.
                  `const __base = ${JSON.stringify(href)}; const __imp = self.importScripts.bind(self);\n` +
                  `self.importScripts = (...u) => __imp(...u.map((x) => new URL(x, __base).href));\n` +
                  `__imp(__base);`;
            const blob = new g.Blob([boot], { type: "text/javascript" });
            return new Original(g.URL.createObjectURL(blob), options);
          }
        } catch {
          // a security policy that forbids blob workers: start it unprotected
        }
        return new Original(url, options);
      };
      Wrapped.prototype = Original.prototype;
      return disguise(Wrapped, Original);
    };
    for (const name of ["Worker", "SharedWorker"]) {
      const wrapped = wrapWorker(g[name]);
      if (wrapped) g[name] = wrapped;
    }
  };

  patchRealm(globalThis);
}

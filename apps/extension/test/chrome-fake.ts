/** In-memory stand-ins for the chrome.* APIs the library modules use. */
import { beforeEach, vi } from "vitest";

function area() {
  let data: Record<string, unknown> = {};
  return {
    get: vi.fn(async (keys: string | string[] | null) => {
      if (keys === null) return { ...data };
      const list = Array.isArray(keys) ? keys : [keys];
      return Object.fromEntries(list.filter((k) => k in data).map((k) => [k, structuredClone(data[k])]));
    }),
    set: vi.fn(async (items: Record<string, unknown>) => {
      data = { ...data, ...structuredClone(items) };
    }),
    remove: vi.fn(async (keys: string | string[]) => {
      for (const key of Array.isArray(keys) ? keys : [keys]) delete data[key];
    }),
    reset() {
      data = {};
    },
  };
}

const local = area();
const session = area();

Object.assign(globalThis, { chrome: { storage: { local, session } } });

beforeEach(() => {
  local.reset();
  session.reset();
  vi.unstubAllGlobals();
});

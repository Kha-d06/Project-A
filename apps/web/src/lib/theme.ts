export type ThemePreference = "light" | "dark" | "system";

export const THEME_STORAGE_KEY = "sentinel-theme";
const CHANGE_EVENT = "sentinel-theme-change";

/**
 * Runs before first paint (inlined in <head>) so the page never flashes the wrong
 * theme. Kept dependency-free and tolerant of blocked storage.
 */
export const themeBootScript = `(function(){try{var p=localStorage.getItem("${THEME_STORAGE_KEY}");}catch(e){}var d=p==="dark"||(p!=="light"&&window.matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.dataset.theme=d?"dark":"light";})();`;

export function readThemePreference(): ThemePreference {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    // Storage blocked: fall back to the system setting.
  }
  return "system";
}

function prefersDark(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function paint(preference: ThemePreference) {
  const dark = preference === "dark" || (preference === "system" && prefersDark());
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

export function applyThemePreference(preference: ThemePreference) {
  try {
    if (preference === "system") localStorage.removeItem(THEME_STORAGE_KEY);
    else localStorage.setItem(THEME_STORAGE_KEY, preference);
  } catch {
    // The choice still applies to this page view.
  }
  paint(preference);
  window.dispatchEvent(new Event(CHANGE_EVENT));
}

/** Subscription for useSyncExternalStore: explicit changes, other tabs, and the OS setting. */
export function subscribeToTheme(onChange: () => void): () => void {
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  const onSystemChange = () => {
    if (readThemePreference() === "system") paint("system");
    onChange();
  };
  window.addEventListener(CHANGE_EVENT, onChange);
  window.addEventListener("storage", onChange);
  media.addEventListener("change", onSystemChange);
  return () => {
    window.removeEventListener(CHANGE_EVENT, onChange);
    window.removeEventListener("storage", onChange);
    media.removeEventListener("change", onSystemChange);
  };
}

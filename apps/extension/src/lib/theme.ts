/** Colour theme for the extension's pages and the on-screen assistant. */
export type ThemeSetting = "system" | "light" | "dark";

export async function themeSetting(): Promise<ThemeSetting> {
  try {
    const stored = await chrome.storage.local.get("settings");
    const theme = (stored.settings as { theme?: unknown } | undefined)?.theme;
    return theme === "light" || theme === "dark" ? theme : "system";
  } catch {
    return "system";
  }
}

export function isDark(theme: ThemeSetting): boolean {
  return theme === "dark" || (theme === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
}

/** Sets data-theme on the page; with "system" the stylesheet follows the browser. */
export async function applyTheme(): Promise<ThemeSetting> {
  const theme = await themeSetting();
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  return theme;
}

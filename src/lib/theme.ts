/**
 * Light and dark (black) themes. The palette lives in src/index.css; this sets `data-theme` on
 * <html>. The choice is also kept in localStorage, because settings arrive from the engine only
 * after the first paint: main.tsx applies the cached choice before rendering, so a dark window
 * does not flash white while it starts.
 */
export type ThemePreference = "system" | "light" | "dark";
export type Theme = "light" | "dark";

const STORAGE_KEY = "xkeystore.theme";
const DARK_QUERY = "(prefers-color-scheme: dark)";

export const isThemePreference = (v: unknown): v is ThemePreference => v === "system" || v === "light" || v === "dark";

export function systemTheme(): Theme {
  return typeof window !== "undefined" && window.matchMedia?.(DARK_QUERY).matches ? "dark" : "light";
}

export const resolveTheme = (pref: ThemePreference, system: Theme = systemTheme()): Theme => (pref === "system" ? system : pref);

export function cachedThemePreference(): ThemePreference {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return isThemePreference(v) ? v : "system";
  } catch {
    return "system";
  }
}

/** Applies the theme to the document and remembers the preference for the next start. */
export function applyTheme(pref: ThemePreference): Theme {
  const theme = resolveTheme(pref);
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    /* storage refused: the next start follows the system until settings load */
  }
  return theme;
}

/** Calls `onChange` when the OS switches between light and dark. Returns the unsubscribe. */
export function watchSystemTheme(onChange: () => void): () => void {
  const mq = window.matchMedia?.(DARK_QUERY);
  if (!mq) return () => undefined;
  mq.addEventListener("change", onChange);
  return () => mq.removeEventListener("change", onChange);
}

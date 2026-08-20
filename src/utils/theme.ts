import { getCurrentWindow } from "@tauri-apps/api/window";

export type ThemeMode = "light" | "dark" | "system";

const MEDIA = "(prefers-color-scheme: dark)";

export function resolveDark(mode: ThemeMode): boolean {
  if (mode === "dark") return true;
  if (mode === "light") return false;
  return window.matchMedia(MEDIA).matches;
}

/** Toggle `html.dark` + native title bar theme. */
export function applyTheme(mode: ThemeMode) {
  const dark = resolveDark(mode);
  document.documentElement.classList.toggle("dark", dark);
  void syncNativeTitleBar(mode);
}

async function syncNativeTitleBar(mode: ThemeMode) {
  try {
    const win = getCurrentWindow();
    // null = follow OS; otherwise force light/dark for title bar chrome
    const native = mode === "system" ? null : mode;
    await win.setTheme(native);
  } catch {
    /* browser / no capability — ignore */
  }
}

export function watchSystemTheme(onChange: () => void): () => void {
  const mq = window.matchMedia(MEDIA);
  const handler = () => onChange();
  mq.addEventListener("change", handler);
  return () => mq.removeEventListener("change", handler);
}

export function parseThemeMode(raw: string | undefined): ThemeMode {
  if (raw === "light" || raw === "dark" || raw === "system") return raw;
  return "light";
}

/**
 * The operating system the UI runs on, read synchronously from the webview's user agent
 * (WebView2 on Windows reports "Windows NT", WKWebView "Macintosh", WebKitGTK "Linux"), so pure
 * helpers can use it without waiting for the engine. Anything that is not Windows or macOS is
 * treated as Linux, which shares the POSIX shell conventions with macOS.
 */
export type Os = "windows" | "macos" | "linux";

export function detectOs(userAgent: string = typeof navigator === "undefined" ? "" : navigator.userAgent): Os {
  if (/Windows/i.test(userAgent)) return "windows";
  if (/Macintosh|Mac OS X/i.test(userAgent)) return "macos";
  return "linux";
}

export const OS: Os = detectOs();

/** Quotes one argument for the shell the built-in terminal uses: cmd.exe on Windows, sh elsewhere. */
export function shellQuote(s: string, os: Os = OS): string {
  if (os === "windows") {
    // cmd.exe has no single quotes. Paths cannot contain `"`, so wrapping in double quotes is enough.
    return /^[\w@+=:,./\\-]+$/.test(s) ? s : `"${s.replace(/"/g, '""')}"`;
  }
  return /^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Redirects stdin from the null device, so tools like `openssl s_client` exit instead of waiting. */
export const nullInput = (os: Os = OS) => (os === "windows" ? "<NUL" : "</dev/null");

/** Lists a folder in detail. */
export const listFolderCommand = (dir: string, os: Os = OS) => (os === "windows" ? `dir ${shellQuote(dir, os)}` : `ls -la ${shellQuote(dir, os)}`);

/** Joins a file name to a folder with the separator the folder already uses. */
export const joinPath = (dir: string, name: string) => {
  const sep = dir.includes("\\") && !dir.includes("/") ? "\\" : "/";
  return dir.endsWith(sep) ? `${dir}${name}` : `${dir}${sep}${name}`;
};

/**
 * A shortcut as the platform writes it. Shortcuts are written "Ctrl+S" in the source; on macOS the
 * same keys are ⌘S (the app accepts Ctrl or ⌘). Ctrl+` stays ⌃` there, because macOS keeps ⌘`
 * for switching windows.
 */
export function shortcutLabel(s: string, os: Os = OS): string {
  if (os !== "macos") return s;
  return s
    .replace(/Ctrl[+ ]`/g, "⌃`")
    .replace(/Ctrl[+ ]/g, "⌘")
    .replace(/Shift\+/g, "⇧")
    .replace(/Alt\+/g, "⌥");
}

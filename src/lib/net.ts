/**
 * Splits what was typed into the TLS host field ("https://host:8443/path", "host:443", "[::1]:443",
 * "host") into a host and a port, the way the engine does (parse_target in src-tauri/src/tls.rs),
 * so the UI shows and suggests exactly what will be connected to.
 */
export function parseTlsTarget(input: string, defaultPort: number): { host: string; port: number } | null {
  let s = input.trim();
  for (const prefix of ["https://", "http://", "ldaps://", "tls://"]) {
    if (s.toLowerCase().startsWith(prefix)) s = s.slice(prefix.length);
  }
  s = s.split(/[/?#]/)[0] ?? "";
  s = s.slice(s.lastIndexOf("@") + 1);
  if (!s) return null;
  const portOf = (text: string) => {
    if (!/^\d{1,5}$/.test(text)) return null;
    const n = Number(text);
    return n >= 1 && n <= 65535 ? n : null;
  };
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    if (end < 0) return null;
    const host = s.slice(1, end);
    const rest = s.slice(end + 1);
    if (!rest) return { host, port: defaultPort };
    const port = rest.startsWith(":") ? portOf(rest.slice(1)) : null;
    return port ? { host, port } : null;
  }
  const colons = s.split(":").length - 1;
  if (colons === 1) {
    const [host, p] = s.split(":");
    const port = portOf(p);
    return host && port ? { host, port } : null;
  }
  return { host: s, port: defaultPort };
}

/** host:port for openssl -connect, with IPv6 addresses in brackets. */
export const connectTarget = ({ host, port }: { host: string; port: number }) => `${host.includes(":") ? `[${host}]` : host}:${port}`;

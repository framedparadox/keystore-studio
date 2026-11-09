import type { ConnectionTest } from "../types/crypto";

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

// ======================================================================= Test-NetConnection

export type TncLevel = "standard" | "detailed" | "quiet";
export type TncCommand = { target: string; port: number; level: TncLevel } | { error: string };

/** -CommonTCPPort names, as in Windows PowerShell. */
const COMMON_TCP_PORTS: Record<string, number> = { http: 80, rdp: 3389, smb: 445, winrm: 5985 };

/** Parameters of Test-NetConnection, plus -DetailedInformation as a shorthand for -InformationLevel Detailed. */
const TNC_PARAMS = ["ComputerName", "Port", "CommonTCPPort", "InformationLevel", "DetailedInformation", "TraceRoute", "Hops", "DiagnoseRouting", "ConstrainSourceAddress", "ConstrainInterface"];
const TNC_ALIASES: Record<string, string> = { cn: "ComputerName", remoteaddress: "ComputerName", remoteport: "Port" };

/** Splits a command line into words; quotes group words and are dropped. */
function words(command: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(command))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

/** A parameter name as PowerShell matches it: exactly, by alias, or by a prefix only one parameter has. */
function tncParam(name: string): string | { error: string } {
  const lower = name.toLowerCase();
  const exact = TNC_PARAMS.find((p) => p.toLowerCase() === lower) ?? TNC_ALIASES[lower];
  if (exact) return exact;
  const matches = TNC_PARAMS.filter((p) => p.toLowerCase().startsWith(lower));
  if (matches.length === 1) return matches[0];
  return { error: matches.length ? `-${name} is ambiguous: it could be ${matches.map((p) => `-${p}`).join(", ")}.` : `Test-NetConnection has no parameter -${name}.` };
}

/**
 * `Test-NetConnection` (or `tnc`) typed into the built-in terminal, the way Windows PowerShell reads
 * it, so the same command works on macOS and Linux. Null when the command is anything else.
 * Only the TCP port test is built in: without a port PowerShell pings, which this does not.
 */
export function parseTestNetConnection(command: string): TncCommand | null {
  const w = words(command.trim());
  if (!w.length || !/^(test-netconnection|tnc)$/i.test(w[0])) return null;
  let target: string | undefined;
  let port: number | undefined;
  let level: TncLevel = "standard";
  for (let i = 1; i < w.length; i++) {
    const word = w[i];
    if (!word.startsWith("-")) {
      if (target !== undefined) return { error: `Unexpected argument '${word}'.` };
      target = word;
      continue;
    }
    // -Name value, or -Name:value
    const colon = word.indexOf(":");
    const rawName = colon > 0 ? word.slice(1, colon) : word.slice(1);
    const inline = colon > 0 ? word.slice(colon + 1) : undefined;
    const param = tncParam(rawName);
    if (typeof param !== "string") return param;
    const value = () => inline ?? w[++i];
    switch (param) {
      case "ComputerName": {
        const v = value();
        if (!v) return { error: "-ComputerName needs a host name, IP address or URL." };
        target = v;
        break;
      }
      case "Port": {
        const v = value() ?? "";
        const n = Number(v);
        if (!/^\d{1,5}$/.test(v) || n < 1 || n > 65535) return { error: "-Port needs a number from 1 to 65535." };
        port = n;
        break;
      }
      case "CommonTCPPort": {
        const n = COMMON_TCP_PORTS[(value() ?? "").toLowerCase()];
        if (!n) return { error: "-CommonTCPPort is one of HTTP, RDP, SMB or WINRM." };
        port = n;
        break;
      }
      case "InformationLevel": {
        const v = (value() ?? "").toLowerCase();
        if (v !== "detailed" && v !== "quiet") return { error: "-InformationLevel is Detailed or Quiet." };
        level = v;
        break;
      }
      case "DetailedInformation":
        level = "detailed";
        break;
      default:
        return { error: `-${param} is not built in: this check tests a TCP port. Use -Port, -CommonTCPPort and -InformationLevel.` };
    }
  }
  if (!target) return { error: "Name the server, e.g. Test-NetConnection -ComputerName example.com -Port 443" };
  // A URL or host:port carries its own port, which wins, as in Examine.
  const parsed = parseTlsTarget(target, port ?? 0);
  if (!parsed) return { error: `'${target}' is not a host name, IP address or URL.` };
  if (!parsed.port) return { error: "Add -Port (e.g. -Port 443): the built-in check tests a TCP port; it does not ping." };
  return { target: parsed.host, port: parsed.port, level };
}

/** A PowerShell-style list: names padded to one width, then " : ", continuation lines indented under the value. */
function formatList(rows: [string, string | string[]][]): string {
  const width = Math.max(...rows.map(([k]) => k.length));
  return rows
    .flatMap(([k, v]) => {
      const values = Array.isArray(v) ? (v.length ? v : [""]) : [v];
      return values.map((value, i) => `${i === 0 ? k.padEnd(width) : " ".repeat(width)} : ${value}`.trimEnd());
    })
    .join("\n");
}

const psBool = (b: boolean) => (b ? "True" : "False");

/** The output of Test-NetConnection for a result: warnings first (as PowerShell writes them), then the object. */
export function formatTestNetConnection(
  r: ConnectionTest,
  level: TncLevel
): { warnings: string[]; output: string } {
  const warnings: string[] = [];
  if (r.failure === "name-resolution") warnings.push(`WARNING: Name resolution of ${r.computer_name} failed`);
  else if (!r.tcp_test_succeeded) warnings.push(`WARNING: TCP connect to (${r.remote_address ?? r.computer_name} : ${r.remote_port}) failed`);
  if (level === "quiet") return { warnings, output: psBool(r.tcp_test_succeeded) };
  const rows: [string, string | string[]][] = [
    ["ComputerName", r.computer_name],
    ["RemoteAddress", r.remote_address ?? ""],
    ["RemotePort", String(r.remote_port)],
  ];
  if (level === "detailed") rows.push(["NameResolutionResults", r.name_resolution]);
  rows.push(["InterfaceAlias", r.interface_alias ?? ""], ["SourceAddress", r.source_address ?? ""]);
  if (level === "detailed") {
    rows.push(["NameResolutionTime", `${r.resolve_ms} ms`]);
    if (r.tcp_ms != null) rows.push(["TcpConnectTime", `${r.tcp_ms} ms`]);
  }
  rows.push(["TcpTestSucceeded", psBool(r.tcp_test_succeeded)]);
  return { warnings, output: formatList(rows) };
}

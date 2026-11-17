import React, { useEffect, useState } from "react";
import clsx from "clsx";
import { CheckCircle2, ChevronDown, ChevronRight, CircleDashed, RotateCcw, TerminalSquare, Wrench } from "lucide-react";
import type { ToolStatus } from "../types/crypto";
import { api, errorMessage } from "../lib/api";
import { OS } from "../lib/platform";
import { Button, Card, CardHeader, CodeBlock, PathText, Spinner, useToast } from "./ui";
import { useTerminal } from "./Terminal";

/** Per-OS install command for each tool, shown when it is missing. */
const JDK = {
  macos: "brew install openjdk",
  windows: "winget install EclipseAdoptium.Temurin.21.JDK",
  linux: "sudo apt install default-jdk   # or: sudo dnf install java-21-openjdk",
};

export const INSTALL_HINTS: Record<string, Partial<Record<typeof OS, string>> & { fallback: string; url: string }> = {
  java: { ...JDK, fallback: "Install a JDK for your platform.", url: "https://adoptium.net" },
  keytool: { ...JDK, fallback: "keytool ships with the Java Runtime: install a JDK.", url: "https://adoptium.net" },
  jarsigner: { ...JDK, fallback: "jarsigner ships with the JDK (not with a JRE).", url: "https://adoptium.net" },
  bcprov: {
    macos: "mvn dependency:get -Dartifact=org.bouncycastle:bcprov-jdk18on:LATEST",
    linux: "sudo apt install libbcprov-java   # installs /usr/share/java/bcprov.jar",
    fallback: "Download bcprov-jdk18on-<version>.jar from bouncycastle.org and set BCPROV_JAR to its path.",
    url: "https://www.bouncycastle.org/download/bouncy-castle-java/",
  },
  openssl: {
    macos: "brew install openssl",
    windows: "winget install ShiningLight.OpenSSL",
    linux: "sudo apt install openssl   # or: sudo dnf install openssl",
    fallback: "Install OpenSSL for your platform.",
    url: "https://www.openssl.org/source/",
  },
  "ssh-keygen": {
    macos: "ssh-keygen ships with macOS",
    windows: "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0",
    linux: "sudo apt install openssh-client   # or: sudo dnf install openssh-clients",
    fallback: "Install the OpenSSH client.",
    url: "https://www.openssh.com/portable.html",
  },
  puttygen: {
    macos: "brew install putty",
    windows: "winget install PuTTY.PuTTY",
    linux: "sudo apt install putty-tools   # or: sudo dnf install putty",
    fallback: "Install PuTTY, which includes PuTTYgen.",
    url: "https://www.chiark.greenend.org.uk/~sgtatham/putty/",
  },
};

/** A command that shows the tool works, for "Try in terminal". */
const TRY_COMMANDS: Record<string, string> = {
  java: "java -version",
  keytool: "keytool -help",
  jarsigner: "jarsigner -help",
  openssl: "openssl version -a",
  "ssh-keygen": "ssh -V",
  puttygen: "puttygen --version",
};

const GROUPS: { id: string; label: string }[] = [
  { id: "java", label: "Java" },
  { id: "openssl", label: "OpenSSL" },
  { id: "ssh", label: "SSH" },
];

const ToolRow: React.FC<{ tool: ToolStatus; open: boolean; onToggle: () => void }> = ({ tool, open, onToggle }) => {
  const { open: openTerminal } = useTerminal();
  const hint = INSTALL_HINTS[tool.id];
  const install = hint ? hint[OS] ?? null : null;
  const tryCommand = TRY_COMMANDS[tool.id];
  const StatusIcon = tool.available ? CheckCircle2 : CircleDashed;
  const status = tool.available ? "Found" : "Not found";
  const panelId = `tool-panel-${tool.id}`;
  return (
    <li className="border-t border-line first:border-t-0" data-testid={`settings-tool-${tool.id}`} data-available={tool.available}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={panelId}
        className="w-full grid grid-cols-[1rem_1rem_minmax(7rem,10rem)_1fr] @2xl:grid-cols-[1rem_1rem_minmax(8rem,12rem)_minmax(6rem,14rem)_1fr] items-center gap-x-3 px-3 py-2.5 text-left text-[13px] rounded-control hover:bg-surface-2 transition cursor-pointer"
      >
        {open ? <ChevronDown className="w-4 h-4 text-subtle" aria-hidden /> : <ChevronRight className="w-4 h-4 text-subtle" aria-hidden />}
        <span role="img" aria-label={status} title={status} className={tool.available ? "text-success" : "text-faint"}>
          <StatusIcon className="w-4 h-4" aria-hidden />
        </span>
        <span className="font-medium text-ink truncate">{tool.name}</span>
        <span className={clsx("font-mono text-[12px] truncate", tool.available ? "text-ink-2" : "text-faint")} title={tool.version ?? undefined}>
          {tool.available ? tool.version ?? "version unknown" : "not found"}
        </span>
        <span className="hidden @2xl:block min-w-0 font-mono text-[12px] text-faint truncate" title={tool.path ?? undefined}>
          {tool.path ?? ""}
        </span>
      </button>
      {open && (
        <div id={panelId} className="pl-[2.75rem] pr-3 pb-3.5 space-y-3 text-[13px]">
          <p className="text-muted">{tool.description}</p>
          <div>
            <div className="text-[11.5px] font-semibold uppercase tracking-[0.04em] text-faint mb-1">Used by</div>
            <ul className="list-disc pl-4 text-ink-2 space-y-0.5">
              {tool.used_by.map((u) => (
                <li key={u}>{u}</li>
              ))}
            </ul>
          </div>
          {tool.available ? (
            <div className="flex flex-wrap items-center gap-3">
              {tool.path && <PathText path={tool.path} />}
              {tryCommand && (
                <Button size="sm" icon={TerminalSquare} onClick={() => openTerminal(tryCommand)} data-testid={`settings-tool-${tool.id}-try`}>
                  Try in terminal
                </Button>
              )}
            </div>
          ) : (
            <div className="space-y-2">
              {install && <CodeBlock label="Install" value={install} testId={`settings-tool-${tool.id}-install`} />}
              {hint && (
                <p className="text-muted">
                  {install ? "Or see " : `${hint.fallback} `}
                  <a href={hint.url} target="_blank" rel="noreferrer" className="text-brand hover:underline break-all">
                    {hint.url}
                  </a>
                </p>
              )}
              <p className="text-faint text-[12px]">Not on your PATH{tool.id === "bcprov" ? ", BCPROV_JAR, /usr/share/java or ~/.m2" : ""}. Keystore Studio works without it; only the commands above need it.</p>
            </div>
          )}
        </div>
      )}
    </li>
  );
};

/**
 * Settings → Tools: every command-line tool Keystore Studio refers to, grouped by family, one row
 * each. A row expands to say what uses the tool and how to install it; missing tools start open.
 */
export const ToolsPanel: React.FC = () => {
  const toast = useToast();
  const [tools, setTools] = useState<ToolStatus[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const load = () => {
    setLoading(true);
    api
      .toolStatus()
      .then((list) => {
        setTools(list);
        setExpanded(new Set(list.filter((t) => !t.available).map((t) => t.id)));
      })
      .catch((err) => toast.error(`Could not check installed tools: ${errorMessage(err)}`))
      .finally(() => setLoading(false));
  };
  useEffect(load, []); // eslint-disable-line react-hooks/exhaustive-deps

  const found = tools?.filter((t) => t.available).length ?? 0;
  const toggle = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <Card className="space-y-4 @3xl:col-span-2" data-testid="settings-tools">
      <div className="flex flex-col @xl:flex-row @xl:items-start @xl:justify-between gap-3">
        <CardHeader
          title="Command-line tools"
          subtitle="Optional. The engine is self-contained; the terminal, the command hints and the Bouncy Castle keytool commands use these when they are installed."
          icon={Wrench}
          className="!mb-0"
        />
        <div className="flex items-center gap-3 shrink-0">
          {tools && (
            <span className="text-[13px] text-muted tabular-nums" data-testid="settings-tools-summary">
              {found} of {tools.length} found
            </span>
          )}
          <Button icon={RotateCcw} onClick={load} disabled={loading} data-testid="settings-tools-recheck">
            {loading ? "Checking…" : "Re-check"}
          </Button>
        </div>
      </div>
      {!tools ? (
        <div className="flex items-center gap-2.5 text-[13px] text-muted py-2">
          {loading ? <Spinner /> : null} {loading ? "Checking installed tools…" : "The tool check did not run."}
        </div>
      ) : (
        <div className="space-y-4">
          {GROUPS.map((g) => {
            const rows = tools.filter((t) => t.group === g.id);
            if (!rows.length) return null;
            return (
              <section key={g.id} aria-labelledby={`tools-group-${g.id}`}>
                <h3 id={`tools-group-${g.id}`} className="px-3 mb-1 text-[11px] font-semibold uppercase tracking-[0.06em] text-faint">
                  {g.label}
                </h3>
                <ul className="rounded-card border border-line">
                  {rows.map((t) => (
                    <ToolRow key={t.id} tool={t} open={expanded.has(t.id)} onToggle={() => toggle(t.id)} />
                  ))}
                </ul>
              </section>
            );
          })}
        </div>
      )}
    </Card>
  );
};

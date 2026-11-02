import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Maximize2, Minimize2, Play, TerminalSquare, X } from "lucide-react";

interface TerminalApi {
  /** Open the terminal panel, optionally pre-filling the prompt (never auto-runs). */
  open: (command?: string) => void;
  toggle: () => void;
}

const TerminalContext = createContext<TerminalApi>({ open: () => {}, toggle: () => {} });
export const useTerminal = () => useContext(TerminalContext);

interface Line {
  kind: "cmd" | "out" | "err" | "info";
  text: string;
}

interface TerminalOutput {
  stdout: string;
  stderr: string;
  code: number;
  cwd: string;
}

export const TerminalProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [prefill, setPrefill] = useState<{ command: string; nonce: number } | null>(null);

  const open = useCallback((command?: string) => {
    setIsOpen(true);
    if (command !== undefined) setPrefill({ command, nonce: Date.now() });
  }, []);
  const toggle = useCallback(() => setIsOpen((v) => !v), []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "`") {
        e.preventDefault();
        setIsOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <TerminalContext.Provider value={{ open, toggle }}>
      {children}
      <TerminalPanel isOpen={isOpen} prefill={prefill} onClose={() => setIsOpen(false)} />
    </TerminalContext.Provider>
  );
};

/** A suggested command with a one-click "open in terminal" action. Used wherever a task has a CLI equivalent. */
export const TerminalHint: React.FC<{ command: string; label?: string }> = ({ command, label = "Run in terminal" }) => {
  const { open } = useTerminal();
  return (
    <div className="flex items-center gap-2 rounded-control bg-term-bg px-3 py-2 text-[11.5px] font-mono text-term-fg">
      <span className="text-subtle select-none">$</span>
      <code className="flex-1 truncate select-text" title={command}>
        {command}
      </code>
      <button
        onClick={() => open(command)}
        className="inline-flex items-center gap-1 rounded-full bg-white/10 px-2.5 py-0.5 font-sans text-[11px] font-semibold text-white hover:bg-white/20 cursor-pointer"
      >
        <Play className="w-3 h-3" />
        {label}
      </button>
    </div>
  );
};

const TerminalPanel: React.FC<{
  isOpen: boolean;
  prefill: { command: string; nonce: number } | null;
  onClose: () => void;
}> = ({ isOpen, prefill, onClose }) => {
  const [lines, setLines] = useState<Line[]>([
    { kind: "info", text: "xkeystore terminal — commands run in your login shell. Ctrl+` toggles this panel." },
  ]);
  const [input, setInput] = useState("");
  const [cwd, setCwd] = useState<string | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!prefill) return;
    setInput(prefill.command);
    inputRef.current?.focus();
  }, [prefill]);

  useEffect(() => {
    if (isOpen) inputRef.current?.focus();
  }, [isOpen]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [lines, isOpen]);

  const run = async () => {
    const command = input.trim();
    if (!command || busy) return;
    setInput("");
    setCursor(null);
    setHistory((h) => [...h, command]);

    if (command === "clear") {
      setLines([]);
      return;
    }
    setLines((l) => [...l, { kind: "cmd", text: `${shortPath(cwd)} $ ${command}` }]);
    setBusy(true);
    try {
      const res = await invoke<TerminalOutput>("run_terminal_command", { command, cwd });
      setCwd(res.cwd);
      setLines((l) => [
        ...l,
        ...(res.stdout ? [{ kind: "out" as const, text: res.stdout }] : []),
        ...(res.stderr ? [{ kind: "err" as const, text: res.stderr.replace(/\n$/, "") }] : []),
        ...(res.code !== 0 ? [{ kind: "info" as const, text: `exit ${res.code}` }] : []),
      ]);
    } catch (e) {
      setLines((l) => [
        ...l,
        { kind: "err", text: `Terminal needs the desktop app (${e instanceof Error ? e.message : String(e)})` },
      ]);
    } finally {
      setBusy(false);
      inputRef.current?.focus();
    }
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      run();
    } else if (e.key === "ArrowUp" && history.length) {
      e.preventDefault();
      const next = cursor === null ? history.length - 1 : Math.max(0, cursor - 1);
      setCursor(next);
      setInput(history[next]);
    } else if (e.key === "ArrowDown" && cursor !== null) {
      e.preventDefault();
      const next = cursor + 1;
      if (next >= history.length) {
        setCursor(null);
        setInput("");
      } else {
        setCursor(next);
        setInput(history[next]);
      }
    } else if (e.key === "l" && e.ctrlKey) {
      e.preventDefault();
      setLines([]);
    }
  };

  if (!isOpen) return null;

  return (
    <section
      aria-label="Terminal"
      className={`fixed left-[88px] right-4 bottom-3 z-40 flex flex-col overflow-hidden rounded-panel border border-white/10 bg-term-bg shadow-2xl select-text ${
        expanded ? "top-20" : "h-[300px]"
      }`}
    >
      <header className="flex items-center justify-between border-b border-white/10 px-4 py-2 text-term-fg select-none">
        <div className="flex items-center gap-2 text-[12px] font-semibold">
          <TerminalSquare className="w-4 h-4 text-brand-soft" />
          Terminal
          <span className="font-mono font-normal text-subtle">{shortPath(cwd)}</span>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setExpanded((v) => !v)}
            aria-label={expanded ? "Shrink terminal" : "Expand terminal"}
            className="rounded-full p-1.5 text-subtle hover:bg-white/10 hover:text-white cursor-pointer"
          >
            {expanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
          <button
            onClick={onClose}
            aria-label="Close terminal"
            className="rounded-full p-1.5 text-subtle hover:bg-white/10 hover:text-white cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </header>

      <div
        ref={scrollRef}
        onClick={() => inputRef.current?.focus()}
        className="flex-1 overflow-y-auto px-4 py-3 font-mono text-[12px] leading-relaxed"
      >
        {lines.map((l, i) => (
          <pre
            key={i}
            className={`whitespace-pre-wrap break-words ${
              l.kind === "cmd" ? "text-brand-soft" : l.kind === "err" ? "text-[#fca5a5]" : l.kind === "info" ? "text-subtle" : "text-term-fg"
            }`}
          >
            {l.text}
          </pre>
        ))}
        <div className="flex items-center gap-2 text-term-fg">
          <span className="text-brand-soft">{shortPath(cwd)} $</span>
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            disabled={busy}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            aria-label="Terminal input"
            className="flex-1 bg-transparent outline-none caret-white"
          />
        </div>
      </div>
    </section>
  );
};

function shortPath(p?: string) {
  if (!p) return "~";
  const parts = p.split("/").filter(Boolean);
  return parts.length ? parts[parts.length - 1] : "/";
}

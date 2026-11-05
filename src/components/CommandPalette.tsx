import React, { useEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import { FilePlus2, FolderArchive, FolderOpen, KeyRound, Lock, Redo2, Save, Search, TerminalSquare, Undo2, X } from "lucide-react";
import { useStore } from "../state/store";
import { NAV_GROUPS, PAGE_TITLES } from "./Sidebar";
import { useTerminal } from "./Terminal";
import { cnOf } from "../lib/keystore";

interface Command {
  id: string;
  label: string;
  hint?: string;
  group: string;
  icon: React.ElementType;
  run: () => void;
  disabled?: boolean;
}

export const CommandPalette: React.FC<{ open: boolean; onClose: () => void }> = ({ open, onClose }) => {
  const store = useStore();
  const { toggle } = useTerminal();
  const [q, setQ] = useState("");
  const [index, setIndex] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (open) {
      setQ("");
      setIndex(0);
      window.setTimeout(() => input.current?.focus(), 20);
    }
  }, [open]);

  const commands: Command[] = useMemo(() => {
    const ks = store.activeKeystore;
    const list: Command[] = [
      { id: "open", label: "Open keystore or file…", group: "Actions", icon: FolderOpen, run: () => store.openFiles(), hint: "Ctrl+O" },
      { id: "new", label: "New keystore…", group: "Actions", icon: FilePlus2, run: () => store.setNewKeystoreOpen(true), hint: "Ctrl+N" },
      { id: "save", label: ks ? `Save ${ks.name}` : "Save", group: "Actions", icon: Save, run: () => ks && store.save(ks.id), disabled: !ks || ks.sealed, hint: "Ctrl+S" },
      { id: "saveas", label: ks ? `Save ${ks.name} as…` : "Save as…", group: "Actions", icon: Save, run: () => ks && store.save(ks.id, { saveAs: true }), disabled: !ks || ks.sealed, hint: "Ctrl+Shift+S" },
      { id: "close", label: ks ? `Close ${ks.name}` : "Close keystore", group: "Actions", icon: X, run: () => ks && store.closeKeystore(ks.id), disabled: !ks },
      { id: "undo", label: "Undo", group: "Actions", icon: Undo2, run: store.undo, disabled: !store.canUndo, hint: "Ctrl+Z" },
      { id: "redo", label: "Redo", group: "Actions", icon: Redo2, run: store.redo, disabled: !store.canRedo, hint: "Ctrl+Shift+Z" },
      { id: "terminal", label: "Toggle terminal", group: "Actions", icon: TerminalSquare, run: toggle, hint: "Ctrl+`" },
      store.vault.unlocked
        ? { id: "lock", label: "Lock vault", group: "Actions", icon: Lock, run: () => store.lockVault() }
        : { id: "unlock", label: store.vault.exists ? "Unlock vault…" : "Set up vault…", group: "Actions", icon: Lock, run: () => store.requestVaultUnlock() },
      ...NAV_GROUPS.flatMap((g) => g.items).concat([{ id: "settings", label: "Settings", icon: KeyRound, shortcut: "8" }]).map((item) => ({
        id: `nav-${item.id}`,
        label: `Go to ${PAGE_TITLES[item.id]}`,
        group: "Pages",
        icon: item.icon,
        run: () => store.setTab(item.id),
        hint: `Ctrl+${item.shortcut}`,
      })),
      ...store.keystores.map((k) => ({
        id: `ks-${k.id}`,
        label: k.name,
        hint: k.sealed ? "locked" : `${k.entries.length} entries`,
        group: "Keystores",
        icon: FolderArchive,
        run: () => {
          store.selectKeystore(k.id);
          store.setTab("keystores");
        },
      })),
      ...store.keystores.flatMap((k) =>
        k.entries.map((e) => ({
          id: `entry-${e.id}`,
          label: e.alias,
          hint: `${e.entry_type === "SecretKey" ? e.algorithm : cnOf(e.subject)} · ${k.name}`,
          group: "Entries",
          icon: KeyRound,
          run: () => {
            store.selectKeystore(k.id);
            store.setTab("keystores");
          },
        }))
      ),
      ...store.recentFiles.map((f) => ({ id: `recent-${f.path}`, label: f.name, hint: f.path, group: "Recent files", icon: FolderOpen, run: () => store.openFiles([f.path]) })),
    ];
    return list;
  }, [store, toggle]);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    const base = commands.filter((c) => !c.disabled);
    if (!s) return base.filter((c) => c.group !== "Entries").slice(0, 40);
    return base.filter((c) => c.label.toLowerCase().includes(s) || (c.hint ?? "").toLowerCase().includes(s)).slice(0, 60);
  }, [commands, q]);

  useEffect(() => setIndex(0), [q]);
  if (!open) return null;
  const run = (c?: Command) => {
    if (!c) return;
    onClose();
    c.run();
  };
  let lastGroup = "";
  return (
    <div className="fixed inset-0 z-[65] bg-ink/30 flex items-start justify-center pt-[12vh] p-4" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div role="dialog" aria-label="Command palette" className="w-full max-w-xl bg-surface rounded-panel border border-line shadow-pop overflow-hidden" data-testid="command-palette">
        <div className="flex items-center gap-2.5 px-4 h-12 border-b border-line">
          <Search className="w-4 h-4 text-subtle" />
          <input
            ref={input}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setIndex((i) => Math.min(filtered.length - 1, i + 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setIndex((i) => Math.max(0, i - 1));
              } else if (e.key === "Enter") {
                e.preventDefault();
                run(filtered[index]);
              } else if (e.key === "Escape") onClose();
            }}
            placeholder="Search pages, actions, keystores and entries…"
            className="flex-1 bg-transparent outline-none text-[14px] text-ink placeholder:text-subtle"
            aria-label="Search commands"
            data-testid="palette-input"
          />
        </div>
        <ul className="max-h-[52vh] overflow-y-auto p-1.5" role="listbox">
          {filtered.length === 0 && <li className="px-3 py-6 text-center text-[13px] text-faint">No matches</li>}
          {filtered.map((c, i) => {
            const header = c.group !== lastGroup ? c.group : null;
            lastGroup = c.group;
            return (
              <React.Fragment key={c.id}>
                {header && <li className="px-3 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-[0.05em] text-subtle">{header}</li>}
                <li role="option" aria-selected={i === index}>
                  <button
                    onMouseEnter={() => setIndex(i)}
                    onClick={() => run(c)}
                    className={clsx("w-full px-3 py-2 rounded-control flex items-center gap-3 text-left cursor-pointer", i === index ? "bg-brand-tint" : "hover:bg-surface-2")}
                  >
                    <c.icon className="w-4 h-4 text-muted shrink-0" />
                    <span className="flex-1 min-w-0 text-[13px] text-ink truncate">{c.label}</span>
                    {c.hint && <span className="text-[11.5px] text-faint truncate max-w-[45%]">{c.hint}</span>}
                  </button>
                </li>
              </React.Fragment>
            );
          })}
        </ul>
      </div>
    </div>
  );
};

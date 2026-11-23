import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { Sidebar } from "./Sidebar";

const state = vi.hoisted(() => ({ vault: { exists: true, unlocked: false } }));

vi.mock("../state/store", () => ({
  useStore: () => ({
    ...state,
    tab: "home",
    keystores: [],
    certificates: [],
    workspaces: [],
    settings: { theme: "light" },
    setTab: vi.fn(),
    openConverter: vi.fn(),
    updateSettings: vi.fn(),
  }),
}));

vi.mock("./Terminal", () => ({ useTerminal: () => ({ toggle: vi.fn() }) }));

describe("sidebar vault status", () => {
  it.each([
    [false, "Vault locked", "lucide-lock"],
    [true, "Vault unlocked", "lucide-lock-open"],
  ])("shows an accessible status icon when unlocked=%s", (unlocked, label, icon) => {
    state.vault = { exists: true, unlocked };
    const markup = renderToStaticMarkup(<Sidebar collapsed={false} onCollapse={() => {}} onExpand={() => {}} />);
    const vault = markup.match(/<button[^>]*data-testid="nav-vault"[\s\S]*?<\/button>/)?.[0];
    expect(vault).toContain(`aria-label="${label}"`);
    expect(vault).toContain(icon);
    expect(vault).not.toContain(">Locked<");
    expect(vault).not.toContain(">Unlocked<");
  });

  it("announces the status in the collapsed rail", () => {
    state.vault = { exists: true, unlocked: true };
    const markup = renderToStaticMarkup(<Sidebar collapsed onCollapse={() => {}} onExpand={() => {}} />);
    expect(markup).toContain('aria-label="Vault unlocked"');
  });

  it("names every collapsed nav button without its tooltip's shortcut text", () => {
    state.vault = { exists: true, unlocked: false };
    const markup = renderToStaticMarkup(<Sidebar collapsed onCollapse={() => {}} onExpand={() => {}} />);
    const buttons = [...markup.matchAll(/<button[^>]*data-testid="nav-([a-z_]+)"[^>]*>/g)];
    expect(buttons.length).toBeGreaterThan(5);
    for (const [tag, id] of buttons) {
      const label = /aria-label="([^"]*)"/.exec(tag)?.[1];
      expect(label, id).toBeTruthy();
      expect(label, id).not.toMatch(/Ctrl|⌘/);
      expect(tag, id).toMatch(/aria-keyshortcuts="Control\+\d"/);
    }
    expect(markup).toContain('aria-label="Vault, locked"');
    expect(markup).toContain('aria-label="Keystores"');
  });

  it("leaves expanded buttons named by their visible label", () => {
    const markup = renderToStaticMarkup(<Sidebar collapsed={false} onCollapse={() => {}} onExpand={() => {}} />);
    const dash = markup.match(/<button[^>]*data-testid="nav-home"[^>]*>/)?.[0];
    expect(dash).not.toContain("aria-label=");
  });

  it("does not show a status before a vault exists", () => {
    state.vault = { exists: false, unlocked: false };
    const markup = renderToStaticMarkup(<Sidebar collapsed={false} onCollapse={() => {}} onExpand={() => {}} />);
    expect(markup).not.toContain('aria-label="Vault locked"');
  });
});

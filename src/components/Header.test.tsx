import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { Header } from "./Header";

const state = vi.hoisted(() => ({ canUndo: false, canRedo: false, tab: "home", vault: { unlocked: false } }));

vi.mock("../state/store", () => ({
  useStore: () => ({
    ...state,
    setTab: vi.fn(),
    undo: vi.fn(),
    redo: vi.fn(),
    openFiles: vi.fn(),
    setNewKeystoreOpen: vi.fn(),
    lockVault: vi.fn(),
  }),
}));

vi.mock("./Terminal", () => ({ useTerminal: () => ({ toggle: vi.fn() }) }));

describe("header history controls", () => {
  it.each([
    [false, false],
    [true, false],
    [false, true],
    [true, true],
  ])("shows available actions before search (undo=%s, redo=%s)", (canUndo, canRedo) => {
    state.canUndo = canUndo;
    state.canRedo = canRedo;
    const markup = renderToStaticMarkup(<Header onOpenPalette={() => {}} />);
    const search = markup.indexOf('data-testid="open-palette"');
    const undo = markup.indexOf('data-testid="undo"');
    const redo = markup.indexOf('data-testid="redo"');

    expect(undo !== -1).toBe(canUndo);
    expect(redo !== -1).toBe(canRedo);
    if (canUndo) expect(undo).toBeLessThan(search);
    if (canRedo) expect(redo).toBeLessThan(search);
    if (canUndo && canRedo) expect(undo).toBeLessThan(redo);
  });

  describe("header vault action", () => {
    it.each([
      ["home", true, true],
      ["vault", true, false],
      ["home", false, false],
      ["vault", false, false],
    ])("shows the lock action on %s when unlocked=%s: %s", (tab, unlocked, visible) => {
      state.tab = tab;
      state.vault.unlocked = unlocked;
      const markup = renderToStaticMarkup(<Header onOpenPalette={() => {}} />);
      const button = markup.match(/<button[^>]*data-testid="header-lock-vault"[\s\S]*?<\/button>/)?.[0];
      expect(Boolean(button)).toBe(visible);
      if (button) {
        expect(button).toContain('aria-label="Lock password vault"');
        expect(button).not.toContain(">Lock password vault<");
        expect(button).toContain("<svg");
      }
    });
  });
});

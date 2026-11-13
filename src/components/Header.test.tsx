import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { Header } from "./Header";

const state = vi.hoisted(() => ({ canUndo: false, canRedo: false }));

vi.mock("../state/store", () => ({
  useStore: () => ({
    ...state,
    tab: "home",
    vault: { unlocked: false },
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
});

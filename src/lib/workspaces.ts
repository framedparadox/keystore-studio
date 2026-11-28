import type { OpenKeystore, Workspace } from "../types/crypto";

/*
 * Folder workspaces. Pure helpers only: no React, no Tauri.
 */

/** True when `path` is a file somewhere under `folder` (either separator). */
export function isInFolder(folder: string, path: string): boolean {
  const root = folder.replace(/[\\/]+$/, "");
  return path.startsWith(root) && /^[\\/]/.test(path.slice(root.length));
}

/** The path of a file relative to the folder it was found in. */
export const relativeToFolder = (folder: string, path: string) => (isInFolder(folder, path) ? path.slice(folder.replace(/[\\/]+$/, "").length + 1) : path);

/** Adds or removes members. A folder workspace remembers removals, so its folder does not undo them. */
export function withMembers(ws: Workspace, ids: string[], include: boolean, updatedAt: string): Workspace {
  const entryIds = include ? [...ws.entryIds, ...ids.filter((id) => !ws.entryIds.includes(id))] : ws.entryIds.filter((id) => !ids.includes(id));
  const next: Workspace = { ...ws, updated_at: updatedAt, entryIds };
  if (ws.folder) {
    const others = (ws.excludedIds ?? []).filter((id) => !ids.includes(id));
    next.excludedIds = include ? others : [...others, ...ids];
  }
  return next;
}

/**
 * Adds to each folder workspace the entries of every open keystore under its folder, except those
 * removed by hand. Returns `list` itself when nothing changes.
 */
export function syncFolderMembers(list: Workspace[], keystores: OpenKeystore[], updatedAt: string): Workspace[] {
  let changed = false;
  const next = list.map((ws) => {
    const { folder } = ws;
    if (!folder) return ws;
    const known = new Set([...ws.entryIds, ...(ws.excludedIds ?? [])]);
    const found = keystores.filter((k) => !k.sealed && isInFolder(folder, k.path)).flatMap((k) => k.entries.map((e) => e.id)).filter((id) => !known.has(id));
    if (!found.length) return ws;
    changed = true;
    return { ...ws, updated_at: updatedAt, entryIds: [...ws.entryIds, ...new Set(found)] };
  });
  return changed ? next : list;
}

export interface DiffSide {
  alias: string;
  fingerprint: string;
}

export interface KeystoreDiff {
  added: string[];
  removed: string[];
  changed: string[];
}

/** Compare two inventories by alias. `changed` is a fingerprint that differs. */
export function diffEntries(left: DiffSide[], right: DiffSide[]): KeystoreDiff {
  const l = new Map(left.map((e) => [e.alias.toLowerCase(), e]));
  const r = new Map(right.map((e) => [e.alias.toLowerCase(), e]));
  const added = [...r.keys()].filter((a) => !l.has(a)).sort();
  const removed = [...l.keys()].filter((a) => !r.has(a)).sort();
  const changed = [...l.keys()].filter((a) => r.has(a) && l.get(a)!.fingerprint !== r.get(a)!.fingerprint).sort();
  return { added, removed, changed };
}

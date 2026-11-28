import { describe, expect, it } from "vitest";
import type { OpenKeystore, Workspace } from "../types/crypto";
import { isInFolder, relativeToFolder, syncFolderMembers, withMembers } from "./workspaces";

const ws = (patch: Partial<Workspace> = {}): Workspace => ({ id: "w", name: "w", description: "", environment: "Development", created_at: "", updated_at: "", entryIds: [], ...patch });
const store = (path: string, aliases: string[], sealed = false) => ({ path, sealed, entries: aliases.map((a) => ({ id: `${path}::${a}` })) }) as unknown as OpenKeystore;

describe("folder workspaces", () => {
  it("matches files under the folder only", () => {
    expect(isInFolder("/a/certs", "/a/certs/x/app.p12")).toBe(true);
    expect(isInFolder("C:\\certs\\", "C:\\certs\\app.p12")).toBe(true);
    expect(isInFolder("/", "/app.p12")).toBe(true);
    expect(isInFolder("/a/certs", "/a/certs-old/app.p12")).toBe(false);
    expect(isInFolder("/a/certs", "")).toBe(false);
    expect(relativeToFolder("/a/certs", "/a/certs/x/app.p12")).toBe("x/app.p12");
  });

  it("adds the entries of open keystores in the folder", () => {
    const list = [ws({ folder: "/f" }), ws({ id: "manual" })];
    const next = syncFolderMembers(list, [store("/f/a.p12", ["one"]), store("/f/sealed.p12", ["two"], true), store("/other/b.p12", ["three"])], "t");
    expect(next[0].entryIds).toEqual(["/f/a.p12::one"]);
    expect(next[1]).toBe(list[1]);
    expect(syncFolderMembers(next, [store("/f/a.p12", ["one"])], "t")).toBe(next);
  });

  it("keeps an entry removed by hand out until it is added back", () => {
    const keystores = [store("/f/a.p12", ["one"])];
    const [synced] = syncFolderMembers([ws({ folder: "/f" })], keystores, "t");
    const removed = withMembers(synced, ["/f/a.p12::one"], false, "t");
    expect(syncFolderMembers([removed], keystores, "t")[0].entryIds).toEqual([]);
    const added = withMembers(removed, ["/f/a.p12::one"], true, "t");
    expect(added.entryIds).toEqual(["/f/a.p12::one"]);
    expect(added.excludedIds).toEqual([]);
  });

  it("records no removals for an ordinary workspace", () => {
    expect(withMembers(ws({ entryIds: ["a"] }), ["a"], false, "t").excludedIds).toBeUndefined();
  });
});

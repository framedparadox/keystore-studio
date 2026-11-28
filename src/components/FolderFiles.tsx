import React, { useCallback, useEffect, useState } from "react";
import { FileBadge, FolderOpen, KeyRound, RefreshCw } from "lucide-react";
import type { FolderScan, Workspace } from "../types/crypto";
import { api, errorMessage } from "../lib/api";
import { relativeToFolder } from "../lib/workspaces";
import { plural } from "../lib/metrics";
import { useStore } from "../state/store";
import { Alert, Badge, Button, Card, Spinner } from "./ui";

/** The keystores and certificate files of a folder workspace, with a way to open each keystore. */
export const FolderFiles: React.FC<{ workspace: Workspace & { folder: string } }> = ({ workspace }) => {
  const { keystores, openFiles, rescanFolderWorkspace, desktop } = useStore();
  const { id, folder } = workspace;
  const [scan, setScan] = useState<FolderScan | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // Showing the folder only lists it; certificates are imported when it is added or rescanned.
  useEffect(() => {
    if (!desktop) return;
    let current = true;
    setScan(null);
    setError("");
    api.scanFolder(folder).then(
      (result) => current && setScan(result),
      (err) => current && setError(errorMessage(err))
    );
    return () => {
      current = false;
    };
  }, [folder, desktop]);

  const rescan = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      setScan(await rescanFolderWorkspace(id));
    } catch (err) {
      setScan(null);
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }, [id, rescanFolderWorkspace]);

  return (
    <Card padded={false} className="mt-4 overflow-hidden" data-testid="folder-files">
      <div className="px-5 py-3 border-b border-line flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-[14px] font-semibold text-ink flex items-center gap-2">
            <FolderOpen className="w-4 h-4 text-muted" /> Folder
          </h3>
          <p className="text-[12px] text-faint truncate font-mono" title={folder}>
            {folder}
          </p>
        </div>
        <Button icon={RefreshCw} onClick={rescan} disabled={busy || !desktop} data-testid="folder-rescan">
          Rescan
        </Button>
      </div>
      {error ? (
        <div className="p-4">
          <Alert tone="danger">{error}</Alert>
        </div>
      ) : !desktop ? (
        <p className="px-5 py-4 text-[13px] text-faint">Folders are read by the desktop app.</p>
      ) : !scan ? (
        <div className="px-5 py-4">
          <Spinner />
        </div>
      ) : scan.files.length === 0 ? (
        <p className="px-5 py-4 text-[13px] text-faint">No keystores or certificate files in this folder.</p>
      ) : (
        <>
          <ul className="max-h-72 overflow-auto divide-y divide-line" aria-label="Files in the folder">
            {scan.files.map((file) => {
              const isStore = file.kind === "keystore";
              const open = keystores.find((k) => k.path === file.path && !k.sealed);
              const Icon = isStore ? KeyRound : FileBadge;
              return (
                <li key={file.path} className="px-5 py-2 flex items-center gap-3" data-testid={`folder-file-${file.name}`}>
                  <Icon className="w-4 h-4 text-muted shrink-0" />
                  <span className="min-w-0 flex-1 text-[13px] text-ink truncate" title={file.path}>
                    {relativeToFolder(folder, file.path)}
                  </span>
                  <Badge>{isStore ? file.keystore_format ?? "Keystore" : "Certificate"}</Badge>
                  {isStore &&
                    (open ? (
                      <Badge tone="success">Open · {plural(open.entries.length, "entry", "entries")}</Badge>
                    ) : (
                      <Button onClick={() => void openFiles([file.path])} data-testid={`folder-open-${file.name}`}>
                        Open
                      </Button>
                    ))}
                </li>
              );
            })}
          </ul>
          <p className="px-5 py-2 border-t border-line text-[12px] text-faint">
            {plural(scan.files.length, "file")}
            {scan.truncated && " · scan limit reached, some files are not listed"}. A keystore's entries join this workspace when you open it.
          </p>
        </>
      )}
    </Card>
  );
};

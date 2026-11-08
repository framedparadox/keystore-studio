import React, { useEffect, useState } from "react";
import clsx from "clsx";
import { UploadCloud } from "lucide-react";
import { isDesktop } from "../lib/api";

/**
 * Window-wide file drop. Uses Tauri's native drag-and-drop so dropped files keep their real
 * paths (a keystore opened this way can be saved back in place).
 */
export function useWindowFileDrop(onPaths: (paths: string[]) => void): boolean {
  const [dragging, setDragging] = useState(false);
  useEffect(() => {
    if (!isDesktop()) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    (async () => {
      const { getCurrentWebview } = await import("@tauri-apps/api/webview");
      const off = await getCurrentWebview().onDragDropEvent((event) => {
        const p = event.payload;
        if (p.type === "enter" || p.type === "over") setDragging(true);
        else if (p.type === "leave") setDragging(false);
        else if (p.type === "drop") {
          setDragging(false);
          if (p.paths.length) onPaths(p.paths);
        }
      });
      if (cancelled) off();
      else unlisten = off;
    })();
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [onPaths]);
  return dragging;
}

export const DropOverlay: React.FC<{ visible: boolean }> = ({ visible }) =>
  visible ? (
    <div className="pointer-events-none fixed inset-0 z-[80] flex items-center justify-center bg-brand/10 border-4 border-dashed border-brand">
      <div className="rounded-panel bg-surface shadow-pop px-8 py-6 text-center">
        <UploadCloud className="w-8 h-8 text-brand mx-auto mb-2" />
        <div className="text-[14px] font-semibold text-ink">Drop to open</div>
        <div className="text-[13px] text-faint mt-1">Keystores open on the Keystores page; certificates, keys, CSRs and CRLs open in Examine; JARs in CA & Signing.</div>
      </div>
    </div>
  ) : null;

/** Click-to-open target with a drag hint. */
export const DropZone: React.FC<{ onClick: () => void; className?: string }> = ({ onClick, className }) => (
  <div
    role="button"
    tabIndex={0}
    onClick={onClick}
    onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onClick()}
    data-testid="dropzone"
    className={clsx(
      "rounded-card border border-dashed px-5 py-6 flex flex-col items-center justify-center text-center transition cursor-pointer border-line-strong bg-surface-2 hover:border-brand hover:bg-brand-tint/60",
      className
    )}
  >
    <span className="w-10 h-10 rounded-card border border-line bg-surface shadow-card flex items-center justify-center mb-3">
      <UploadCloud className="w-5 h-5 text-muted" />
    </span>
    <p className="text-[14px] font-semibold text-ink">
      <span className="text-brand">Click to open</span> or drop files anywhere
    </p>
    <p className="text-[12px] text-faint mt-1 max-w-xs">.p12 .pfx .jks .jceks .pem .crt .cer .der .csr .crl .key .p7b .jar</p>
  </div>
);

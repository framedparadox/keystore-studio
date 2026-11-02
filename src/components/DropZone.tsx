import React, { useCallback, useRef, useState } from "react";
import clsx from "clsx";
import { UploadCloud } from "lucide-react";
import { ACCEPTED_EXTENSIONS } from "../lib/importFile";

/** Drag-and-drop state for any container. Spread `bind` on the element that should accept files. */
export function useFileDrop(onFiles: (files: File[]) => void) {
  const [dragging, setDragging] = useState(false);
  const depth = useRef(0);

  const bind = {
    onDragEnter: (e: React.DragEvent) => {
      if (!e.dataTransfer.types.includes("Files")) return;
      e.preventDefault();
      depth.current += 1;
      setDragging(true);
    },
    onDragOver: (e: React.DragEvent) => {
      if (e.dataTransfer.types.includes("Files")) e.preventDefault();
    },
    onDragLeave: () => {
      depth.current = Math.max(0, depth.current - 1);
      if (depth.current === 0) setDragging(false);
    },
    onDrop: (e: React.DragEvent) => {
      e.preventDefault();
      depth.current = 0;
      setDragging(false);
      const files = Array.from(e.dataTransfer.files);
      if (files.length) onFiles(files);
    },
  };
  return { dragging, bind };
}

interface DropZoneProps {
  dragging: boolean;
  busy?: boolean;
  onFiles: (files: File[]) => void;
}

export const DropZone: React.FC<DropZoneProps> = ({ dragging, busy, onFiles }) => {
  const input = useRef<HTMLInputElement>(null);
  const pick = useCallback(() => input.current?.click(), []);

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={pick}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && pick()}
      className={clsx(
        "rounded-panel border-2 border-dashed px-6 py-5 text-center transition cursor-pointer",
        dragging ? "border-brand bg-brand-tint" : "border-line-strong bg-surface hover:border-brand hover:bg-brand-tint/50"
      )}
    >
      <input
        ref={input}
        type="file"
        multiple
        accept={ACCEPTED_EXTENSIONS}
        className="hidden"
        onChange={(e) => {
          const files = Array.from(e.target.files ?? []);
          if (files.length) onFiles(files);
          e.target.value = "";
        }}
      />
      <UploadCloud className={clsx("w-7 h-7 mx-auto mb-1.5", dragging ? "text-brand" : "text-subtle")} />
      <p className="text-[16px] font-semibold text-ink">
        {busy ? "Reading files…" : dragging ? "Drop to open" : "Drop keystores and certificates here"}
      </p>
      <p className="text-[12.5px] text-muted mt-1">
        or click to browse · .jks .p12 .pfx .jceks .bks .pem .crt .cer .der .csr .crl .key
      </p>
    </div>
  );
};

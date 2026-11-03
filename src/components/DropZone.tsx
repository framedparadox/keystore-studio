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

export const DropZone: React.FC<DropZoneProps & { className?: string }> = ({ dragging, busy, onFiles, className }) => {
  const input = useRef<HTMLInputElement>(null);
  const pick = useCallback(() => input.current?.click(), []);

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={pick}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && pick()}
      className={clsx(
        "rounded-card border border-dashed px-5 py-6 flex flex-col items-center justify-center text-center transition cursor-pointer",
        dragging ? "border-brand bg-brand-tint" : "border-line-strong bg-surface-2 hover:border-brand hover:bg-brand-tint/60",
        className
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
      <span className="w-10 h-10 rounded-card border border-line bg-surface shadow-card flex items-center justify-center mb-3">
        <UploadCloud className={clsx("w-5 h-5", dragging ? "text-brand" : "text-muted")} />
      </span>
      <p className="text-[13.5px] font-semibold text-ink">
        {busy ? "Reading files…" : dragging ? "Drop to open" : (
          <>
            <span className="text-brand">Click to upload</span> or drag and drop
          </>
        )}
      </p>
      <p className="text-[12px] text-faint mt-1 max-w-xs">
        .jks .p12 .pfx .jceks .bks .pem .crt .cer .der .csr .crl .key
      </p>
    </div>
  );
};

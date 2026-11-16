"use client";

import { useEffect, useRef, type ReactNode } from "react";

/** A modal built on the native <dialog>, which handles focus trapping and Escape. */
export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: ReactNode;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      aria-labelledby="dialog-title"
      className="m-auto w-[min(28rem,calc(100vw-2rem))] rounded-panel border border-line bg-surface-raised p-0 text-ink shadow-raised backdrop:bg-black/50 open:animate-fade-up"
    >
      <div className="space-y-4 p-6">
        <div className="space-y-1.5">
          <h2 id="dialog-title" className="font-display text-lg font-semibold">
            {title}
          </h2>
          {description && <div className="text-sm text-ink-muted">{description}</div>}
        </div>
        {children}
      </div>
    </dialog>
  );
}

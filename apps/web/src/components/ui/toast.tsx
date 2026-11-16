"use client";

import { CheckCircle2, CircleAlert, X } from "lucide-react";
import { createContext, useCallback, useContext, useState, type ReactNode } from "react";

import { cn } from "@/lib/cn";

interface Toast {
  id: number;
  tone: "success" | "error";
  message: string;
}

const ToastContext = createContext<((tone: Toast["tone"], message: string) => void) | null>(null);
const TOAST_DURATION_MS = 5000;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const notify = useCallback(
    (tone: Toast["tone"], message: string) => {
      const id = Date.now() + Math.random();
      setToasts((current) => [...current.slice(-2), { id, tone, message }]);
      window.setTimeout(() => dismiss(id), TOAST_DURATION_MS);
    },
    [dismiss],
  );

  return (
    <ToastContext.Provider value={notify}>
      {children}
      <div
        aria-live="polite"
        className="pointer-events-none fixed inset-x-4 bottom-4 z-50 flex flex-col items-center gap-2 sm:inset-x-auto sm:end-6 sm:items-end"
      >
        {toasts.map((toast) => {
          const Icon = toast.tone === "success" ? CheckCircle2 : CircleAlert;
          return (
            <div
              key={toast.id}
              role={toast.tone === "error" ? "alert" : "status"}
              className="pointer-events-auto flex w-full max-w-sm animate-fade-up items-start gap-3 rounded-control border border-line bg-surface-raised px-4 py-3 text-sm shadow-raised"
            >
              <Icon
                aria-hidden
                className={cn(
                  "mt-0.5 size-4 shrink-0",
                  toast.tone === "success" ? "text-accent" : "text-danger",
                )}
              />
              <p className="flex-1 text-ink">{toast.message}</p>
              <button
                type="button"
                onClick={() => dismiss(toast.id)}
                className="text-ink-faint hover:text-ink"
                aria-label="Dismiss notification"
              >
                <X aria-hidden className="size-4" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const notify = useContext(ToastContext);
  if (!notify) throw new Error("useToast must be used inside <ToastProvider>");
  return notify;
}

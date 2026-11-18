import { useId, type ComponentProps, type ReactNode } from "react";

import { cn } from "@/lib/cn";

const control =
  "w-full rounded-control border bg-surface px-3.5 text-ink placeholder:text-ink-faint shadow-[inset_0_1px_2px_rgb(0_0_0/0.04)] " +
  "transition-[border-color,box-shadow] duration-200 focus-visible:outline-none focus-visible:border-accent " +
  "focus-visible:shadow-[0_0_0_4px_color-mix(in_srgb,var(--accent)_18%,transparent)] " +
  "disabled:opacity-60";

function controlClasses(invalid: boolean, className?: string) {
  return cn(
    control,
    invalid ? "border-danger" : "border-line-strong hover:border-ink-faint",
    className,
  );
}

interface FieldProps {
  label: string;
  hint?: ReactNode;
  error?: string;
  children: (props: {
    id: string;
    "aria-invalid": boolean;
    "aria-describedby": string | undefined;
  }) => ReactNode;
}

/** Label, control, hint and error, wired together for assistive technology. */
export function Field({ label, hint, error, children }: FieldProps) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm font-medium text-ink">
        {label}
      </label>
      {children({
        id,
        "aria-invalid": Boolean(error),
        "aria-describedby": [hintId, errorId].filter(Boolean).join(" ") || undefined,
      })}
      {hint && !error && (
        <p id={hintId} className="text-sm text-ink-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} className="text-sm text-danger">
          {error}
        </p>
      )}
    </div>
  );
}

export function Input({ className, ...props }: ComponentProps<"input">) {
  return (
    <input className={controlClasses(Boolean(props["aria-invalid"]), cn("h-11", className))} {...props} />
  );
}

export function Textarea({ className, ...props }: ComponentProps<"textarea">) {
  return (
    <textarea
      className={controlClasses(Boolean(props["aria-invalid"]), cn("min-h-40 py-2.5 leading-relaxed", className))}
      {...props}
    />
  );
}

export function Select({ className, ...props }: ComponentProps<"select">) {
  return <select className={controlClasses(false, cn("h-10 pe-8", className))} {...props} />;
}

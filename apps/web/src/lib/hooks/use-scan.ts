"use client";

import { useEffect, useState } from "react";

import { ApiError, api } from "@/lib/api/client";
import type { Scan } from "@/lib/api/types";
import { isActive } from "@/lib/risk";

// Poll quickly at first (most scans finish in a few seconds), then back off.
const FIRST_POLL_MS = 1000;
const MAX_POLL_MS = 5000;
const BACKOFF = 1.4;

export type ScanState =
  | { phase: "loading" }
  | { phase: "ready"; scan: Scan }
  | { phase: "error"; error: ApiError };

export function useScan(scanId: string, initial?: Scan): ScanState {
  const [state, setState] = useState<ScanState>(
    initial ? { phase: "ready", scan: initial } : { phase: "loading" },
  );

  useEffect(() => {
    const controller = new AbortController();
    let timer: number | undefined;
    let delay = FIRST_POLL_MS;
    let consecutiveFailures = 0;

    const poll = async () => {
      try {
        const scan = await api.scans.get(scanId, controller.signal);
        consecutiveFailures = 0;
        setState({ phase: "ready", scan });
        if (!isActive(scan.status)) return;
      } catch (error) {
        if (controller.signal.aborted) return;
        const apiError =
          error instanceof ApiError ? error : new ApiError(0, "unknown", "Something went wrong.");
        consecutiveFailures += 1;
        // A missing scan will not appear later; a network blip might recover.
        if (apiError.status === 404 || consecutiveFailures >= 3) {
          setState({ phase: "error", error: apiError });
          return;
        }
      }
      timer = window.setTimeout(poll, delay);
      delay = Math.min(delay * BACKOFF, MAX_POLL_MS);
    };

    if (initial && !isActive(initial.status)) return;
    void poll();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [scanId, initial]);

  return state;
}

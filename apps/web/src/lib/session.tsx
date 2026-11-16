"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { api, setCsrfToken } from "./api/client";
import type { SessionInfo, User } from "./api/types";

type SessionState =
  | { status: "loading"; user: null }
  | { status: "signed-out"; user: null }
  | { status: "signed-in"; user: User };

interface SessionContextValue {
  session: SessionState;
  signIn: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, displayName?: string) => Promise<void>;
  signOut: () => Promise<void>;
  updateUser: (user: User) => void;
  /** Forget the session locally, e.g. after the account was deleted. */
  clear: () => void;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<SessionState>({ status: "loading", user: null });

  const adopt = useCallback((info: SessionInfo) => {
    setCsrfToken(info.csrf_token);
    setSession({ status: "signed-in", user: info.user });
  }, []);

  const clear = useCallback(() => {
    setCsrfToken(null);
    setSession({ status: "signed-out", user: null });
  }, []);

  useEffect(() => {
    let cancelled = false;
    api.auth
      .session()
      .then((status) => {
        if (cancelled) return;
        if (status.user && status.csrf_token) adopt({ user: status.user, csrf_token: status.csrf_token });
        else clear();
      })
      .catch(() => {
        // Network failures are treated as signed out too: scanning works without an
        // account, and pages that need one explain why when they load.
        if (!cancelled) clear();
      });
    return () => {
      cancelled = true;
    };
  }, [adopt, clear]);

  const value = useMemo<SessionContextValue>(
    () => ({
      session,
      signIn: async (email, password) => adopt(await api.auth.login({ email, password })),
      register: async (email, password, displayName) =>
        adopt(await api.auth.register({ email, password, display_name: displayName })),
      signOut: async () => {
        try {
          await api.auth.logout();
        } finally {
          clear();
        }
      },
      updateUser: (user) => setSession({ status: "signed-in", user }),
      clear,
    }),
    [session, adopt, clear],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionContextValue {
  const context = useContext(SessionContext);
  if (!context) throw new Error("useSession must be used inside <SessionProvider>");
  return context;
}

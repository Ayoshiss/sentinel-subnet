"use client";

import { useState, useEffect } from "react";

type SessionState = { loaded: boolean; loggedIn: boolean; email: string };

// Reads the (non-httpOnly) session JWT cookie on the client and decodes it.
// Treats an expired token as logged-out.
export function useSession(): SessionState {
  const [state, setState] = useState<SessionState>({ loaded: false, loggedIn: false, email: "" });

  useEffect(() => {
    const m = document.cookie.match(/(?:^| )session=([^;]+)/);
    if (!m) {
      setState({ loaded: true, loggedIn: false, email: "" });
      return;
    }
    try {
      const payload = JSON.parse(atob(m[1].split(".")[1]));
      if (payload.exp && payload.exp * 1000 < Date.now()) {
        setState({ loaded: true, loggedIn: false, email: "" });
        return;
      }
      setState({ loaded: true, loggedIn: true, email: payload.email ?? "" });
    } catch {
      setState({ loaded: true, loggedIn: false, email: "" });
    }
  }, []);

  return state;
}

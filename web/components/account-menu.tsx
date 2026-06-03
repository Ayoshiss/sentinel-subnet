"use client";

import { useState, useRef, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

export function logout(router: { push: (p: string) => void }) {
  document.cookie = "session=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
  router.push("/");
}

export function AccountMenu({ email }: { email: string }) {
  const [open, setOpen] = useState(false);
  const router = useRouter();
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen(!open)} className="flex items-center gap-2.5">
        {email && <span className="text-xs text-[#8A8A8F] hidden sm:block">{email}</span>}
        <div className="w-8 h-8 bg-[#E5392B] rounded-full flex items-center justify-center text-white text-xs font-semibold">
          {email ? email[0].toUpperCase() : "?"}
        </div>
      </button>
      {open && (
        <div className="absolute right-0 mt-2 w-52 bg-[#111113] border border-[#1E1E20] rounded-lg shadow-2xl py-1 z-50">
          <div className="px-3 py-2 text-xs text-[#8A8A8F] border-b border-[#1E1E20] truncate">{email}</div>
          <Link href="/dashboard" onClick={() => setOpen(false)} className="block px-3 py-2 text-sm text-[#ECECEC] hover:bg-[#1E1E20] transition-colors">Dashboard</Link>
          <Link href="/settings" onClick={() => setOpen(false)} className="block px-3 py-2 text-sm text-[#ECECEC] hover:bg-[#1E1E20] transition-colors">Settings</Link>
          <div className="border-t border-[#1E1E20] my-1" />
          <button onClick={() => logout(router)} className="block w-full text-left px-3 py-2 text-sm text-[#E5827B] hover:bg-[#1E1E20] transition-colors">Log out</button>
        </div>
      )}
    </div>
  );
}

"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";

function VerifyInner() {
  const router = useRouter();
  const params = useSearchParams();
  const [status, setStatus] = useState<"verifying" | "error">("verifying");

  useEffect(() => {
    const token = params.get("token");
    if (!token) { setStatus("error"); return; }

    // The Go gateway sets the session cookie and redirects to /dashboard.
    // We just need to hit the verify endpoint directly.
    const gatewayURL = process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";
    window.location.href = `${gatewayURL}/auth/verify?token=${token}`;
  }, [params, router]);

  return (
    <div className="min-h-screen bg-white flex items-center justify-center">
      <div className="text-center">
        {status === "verifying" ? (
          <>
            <svg className="animate-spin w-8 h-8 text-gray-400 mx-auto mb-4" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
            <p className="text-sm text-gray-500">Signing you in…</p>
          </>
        ) : (
          <>
            <p className="text-sm text-red-600 mb-4">Invalid or expired link.</p>
            <a href="/login" className="text-sm text-gray-900 underline">Try again</a>
          </>
        )}
      </div>
    </div>
  );
}

export default function VerifyPage() {
  return (
    <Suspense>
      <VerifyInner />
    </Suspense>
  );
}

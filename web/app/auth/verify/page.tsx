"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";

function VerifyInner() {
  const router = useRouter();
  const params = useSearchParams();
  const [status, setStatus] = useState<"verifying" | "error">("verifying");
  const [errorMsg, setErrorMsg] = useState("Invalid or expired link.");

  useEffect(() => {
    const token = params.get("token");
    if (!token) {
      setStatus("error");
      setErrorMsg("No token found in the link.");
      return;
    }

    const gatewayURL = process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";

    fetch(`${gatewayURL}/auth/verify?token=${token}`)
      .then(async (res) => {
        if (!res.ok) throw new Error("Invalid or expired link");
        const data = await res.json();
        if (!data.token) throw new Error("No token returned");

        // Set session cookie on this domain
        const expires = new Date(Date.now() + 86400 * 1000).toUTCString();
        document.cookie = `session=${data.token}; path=/; expires=${expires}; SameSite=Lax`;

        router.push("/dashboard");
      })
      .catch((err) => {
        setErrorMsg(err.message ?? "Something went wrong.");
        setStatus("error");
      });
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
            <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg className="w-5 h-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12"/>
              </svg>
            </div>
            <p className="text-sm text-gray-700 font-medium mb-1">Link expired</p>
            <p className="text-xs text-gray-400 mb-4">{errorMsg}</p>
            <a href="/login" className="text-sm bg-gray-900 text-white px-4 py-2 rounded-lg hover:bg-gray-700 transition-colors">
              Request a new link
            </a>
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

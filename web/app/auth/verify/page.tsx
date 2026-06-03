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
    <div className="min-h-screen bg-[#0A0A0B] text-[#ECECEC] flex items-center justify-center antialiased">
      <div className="text-center">
        {status === "verifying" ? (
          <>
            <svg className="animate-spin w-8 h-8 text-[#55555B] mx-auto mb-4" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
              <path className="opacity-75" fill="#E5392B" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
            <p className="text-sm text-[#8A8A8F]">Signing you in…</p>
          </>
        ) : (
          <>
            <div className="w-12 h-12 bg-[#E5392B]/10 border border-[#E5392B]/30 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg className="w-5 h-5 text-[#E5392B]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12"/>
              </svg>
            </div>
            <p className="text-sm text-[#ECECEC] font-medium mb-1">Link expired</p>
            <p className="text-xs text-[#55555B] mb-4">{errorMsg}</p>
            <a href="/login" className="text-sm bg-[#E5392B] text-white px-4 py-2 rounded-lg hover:bg-[#cf3325] transition-colors">
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

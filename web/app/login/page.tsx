"use client";

import { useState } from "react";
import Link from "next/link";
import { Logo, EyeMark } from "@/components/brand";

type Step = "form" | "loading" | "sent" | "error";

export default function Login() {
  const [step, setStep] = useState<Step>("form");
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setStep("loading");
    try {
      const gatewayURL = process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";
      const res = await fetch(`${gatewayURL}/auth/request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      if (!res.ok) throw new Error("Failed to send login link");
      setStep("sent");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Something went wrong");
      setStep("error");
    }
  }

  return (
    <div className="min-h-screen bg-[#0A0A0B] text-[#ECECEC] flex flex-col antialiased selection:bg-[#E5392B]/30">
      <header className="border-b border-[#1E1E20] px-6 h-16 flex items-center justify-between">
        <Link href="/"><Logo /></Link>
        <Link href="/signup" className="text-sm text-[#8A8A8F] hover:text-[#ECECEC] transition-colors">
          No account? Sign up →
        </Link>
      </header>

      <div className="flex-1 flex items-center justify-center px-6">
        <div className="w-full max-w-sm">

          {(step === "form" || step === "loading") && (
            <>
              <h1 className="text-2xl font-semibold tracking-tight mb-1">Sign in</h1>
              <p className="text-sm text-[#8A8A8F] mb-8">We&apos;ll email you a magic link — no password needed.</p>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-[#8A8A8F] mb-1.5">Email</label>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    className="w-full bg-[#111113] border border-[#1E1E20] rounded-lg px-3.5 py-2.5 text-sm text-[#ECECEC] placeholder-[#55555B] focus:outline-none focus:border-[#E5392B]/50 transition"
                  />
                </div>
                <button
                  type="submit"
                  disabled={step === "loading" || !email}
                  className="w-full bg-[#E5392B] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#cf3325] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {step === "loading" ? (
                    <span className="flex items-center justify-center gap-2">
                      <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                      </svg>
                      Sending…
                    </span>
                  ) : "Send magic link →"}
                </button>
              </form>
            </>
          )}

          {step === "sent" && (
            <div className="text-center">
              <EyeMark size={44} className="mx-auto mb-5" />
              <h1 className="text-xl font-semibold tracking-tight mb-2">Check your email</h1>
              <p className="text-sm text-[#8A8A8F] mb-1">We sent a magic link to</p>
              <p className="text-sm font-medium text-[#ECECEC] mb-6">{email}</p>
              <p className="text-xs text-[#55555B]">Link expires in 15 minutes. Check spam if you don&apos;t see it.</p>
              <button onClick={() => setStep("form")} className="mt-6 text-sm text-[#8A8A8F] hover:text-[#ECECEC] transition-colors">
                Use a different email
              </button>
            </div>
          )}

          {step === "error" && (
            <>
              <h1 className="text-2xl font-semibold tracking-tight mb-6">Something went wrong</h1>
              <div className="bg-[#E5392B]/10 border border-[#E5392B]/30 rounded-lg p-4 text-sm text-[#E5827B] mb-6">{error}</div>
              <button onClick={() => setStep("form")} className="w-full border border-[#1E1E20] text-[#ECECEC] py-2.5 rounded-lg text-sm font-medium hover:border-[#33333A] transition-colors">
                Try again
              </button>
            </>
          )}

        </div>
      </div>
    </div>
  );
}

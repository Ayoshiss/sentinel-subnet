"use client";

import { useState } from "react";
import Link from "next/link";

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
    <div className="min-h-screen bg-white flex flex-col">
      <header className="border-b border-gray-100 px-6 h-14 flex items-center justify-between">
        <Link href="/" className="font-semibold text-gray-900 tracking-tight">TAO Gateway</Link>
        <Link href="/signup" className="text-sm text-gray-500 hover:text-gray-900 transition-colors">
          No account? Sign up →
        </Link>
      </header>

      <div className="flex-1 flex items-center justify-center px-6">
        <div className="w-full max-w-sm">

          {(step === "form" || step === "loading") && (
            <>
              <h1 className="text-2xl font-bold text-gray-900 mb-1">Sign in</h1>
              <p className="text-sm text-gray-500 mb-8">We&apos;ll email you a magic link — no password needed.</p>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-gray-700 mb-1.5">Email</label>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    className="w-full border border-gray-200 rounded-lg px-3.5 py-2.5 text-sm text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:border-transparent transition"
                  />
                </div>
                <button
                  type="submit"
                  disabled={step === "loading" || !email}
                  className="w-full bg-gray-900 text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-gray-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
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
              <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-6 h-6 text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
                </svg>
              </div>
              <h1 className="text-xl font-bold text-gray-900 mb-2">Check your email</h1>
              <p className="text-sm text-gray-500 mb-1">We sent a magic link to</p>
              <p className="text-sm font-medium text-gray-900 mb-6">{email}</p>
              <p className="text-xs text-gray-400">Link expires in 15 minutes. Check your spam folder if you don&apos;t see it.</p>
              <button
                onClick={() => setStep("form")}
                className="mt-6 text-sm text-gray-500 hover:text-gray-900 transition-colors"
              >
                Use a different email
              </button>
            </div>
          )}

          {step === "error" && (
            <>
              <h1 className="text-2xl font-bold text-gray-900 mb-6">Something went wrong</h1>
              <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-700 mb-6">{error}</div>
              <button onClick={() => setStep("form")} className="w-full border border-gray-200 text-gray-700 py-2.5 rounded-lg text-sm font-medium hover:border-gray-400 transition-colors">
                Try again
              </button>
            </>
          )}

        </div>
      </div>
    </div>
  );
}

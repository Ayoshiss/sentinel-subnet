"use client";

import { useState } from "react";
import Link from "next/link";

type Step = "form" | "loading" | "done" | "error";

export default function Signup() {
  const [step, setStep] = useState<Step>("form");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setStep("loading");
    try {
      const gatewayURL = process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";
      const adminSecret = process.env.NEXT_PUBLIC_ADMIN_SECRET ?? "";
      const custRes = await fetch(`${gatewayURL}/admin/customers`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Admin-Secret": adminSecret },
        body: JSON.stringify({ email, name }),
      });
      if (!custRes.ok) throw new Error((await custRes.json()).error ?? "Failed to create account");
      const { customer_id } = await custRes.json();
      const keyRes = await fetch(`${gatewayURL}/admin/keys`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Admin-Secret": adminSecret },
        body: JSON.stringify({ customer_id, name: "default" }),
      });
      if (!keyRes.ok) throw new Error("Failed to generate API key");
      const { key } = await keyRes.json();
      setApiKey(key);
      setStep("done");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Something went wrong");
      setStep("error");
    }
  }

  function copyKey() {
    navigator.clipboard.writeText(apiKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="min-h-screen bg-white flex flex-col">
      {/* Nav */}
      <header className="border-b border-gray-100 px-6 h-14 flex items-center">
        <Link href="/" className="font-semibold text-gray-900 tracking-tight">TAO Gateway</Link>
      </header>

      <div className="flex-1 flex">
        {/* Left panel — form */}
        <div className="flex-1 flex items-center justify-center px-6 py-12">
          <div className="w-full max-w-sm">

            {(step === "form" || step === "loading") && (
              <>
                <div className="mb-8">
                  <h1 className="text-2xl font-bold text-gray-900 mb-1">Create your account</h1>
                  <p className="text-sm text-gray-500">Free to start. 100k tokens included. No card required.</p>
                </div>
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1.5">Name</label>
                    <input
                      type="text"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="Ada Lovelace"
                      className="w-full border border-gray-200 rounded-lg px-3.5 py-2.5 text-sm text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-gray-900 focus:border-transparent transition"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1.5">Work email</label>
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="ada@company.com"
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
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                        Creating account…
                      </span>
                    ) : "Create free account →"}
                  </button>
                </form>
                <p className="text-xs text-gray-400 mt-4 text-center">
                  By signing up you agree to our <a href="#" className="underline hover:text-gray-600">Terms of Service</a>.
                </p>
              </>
            )}

            {step === "done" && (
              <>
                <div className="flex items-center gap-2 mb-6">
                  <div className="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center">
                    <svg className="w-4 h-4 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                  <span className="text-sm font-medium text-green-700">Account created</span>
                </div>

                <h1 className="text-2xl font-bold text-gray-900 mb-1">Your API key</h1>
                <p className="text-sm text-gray-500 mb-6">Copy and store this key — we won&apos;t show it again.</p>

                {/* Key */}
                <div className="border border-gray-200 rounded-lg mb-6 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-3 bg-gray-50 border-b border-gray-200">
                    <span className="text-xs font-medium text-gray-500 uppercase tracking-widest">API Key</span>
                    <button onClick={copyKey} className={`text-xs font-medium px-3 py-1 rounded-md transition-colors ${copied ? "bg-green-100 text-green-700" : "bg-white border border-gray-200 text-gray-600 hover:border-gray-400"}`}>
                      {copied ? "✓ Copied" : "Copy"}
                    </button>
                  </div>
                  <div className="px-4 py-3">
                    <code className="text-xs text-gray-700 break-all leading-relaxed">{apiKey}</code>
                  </div>
                </div>

                {/* Quick start */}
                <div className="border border-gray-200 rounded-lg overflow-hidden mb-6">
                  <div className="bg-gray-50 border-b border-gray-200 px-4 py-2.5 flex items-center gap-2">
                    <div className="flex gap-1">
                      <span className="w-2.5 h-2.5 rounded-full bg-red-400" />
                      <span className="w-2.5 h-2.5 rounded-full bg-yellow-400" />
                      <span className="w-2.5 h-2.5 rounded-full bg-green-400" />
                    </div>
                    <span className="text-xs text-gray-400 font-mono ml-1">Quick start</span>
                  </div>
                  <pre className="px-4 py-3 text-xs font-mono text-gray-600 overflow-x-auto leading-relaxed bg-white">{`curl https://api.taogateway.dev/v1/chat/completions \\
  -H "Authorization: Bearer ${apiKey.slice(0, 24)}..." \\
  -H "Content-Type: application/json" \\
  -d '{"model":"gpt-4o","messages":[
    {"role":"user","content":"Hello!"}
  ]}'`}</pre>
                </div>

                <Link href="/dashboard" className="block text-center w-full bg-gray-900 text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-gray-700 transition-colors">
                  Go to dashboard →
                </Link>
              </>
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

        {/* Right panel — feature list */}
        <div className="hidden lg:flex w-96 bg-gray-50 border-l border-gray-100 flex-col justify-center px-12 py-12">
          <h2 className="text-sm font-semibold text-gray-900 mb-6">What you get</h2>
          <div className="space-y-6">
            {[
              { icon: "⚡", title: "OpenAI-compatible", desc: "Change one URL. Your existing SDK works unchanged." },
              { icon: "💸", title: "90% cheaper", desc: "Bittensor miners compete on price. You win." },
              { icon: "🔀", title: "Smart routing", desc: "Best subnet selected per request automatically." },
              { icon: "📊", title: "Usage dashboard", desc: "Real-time token usage, cost, and latency data." },
            ].map((f) => (
              <div key={f.title} className="flex gap-3">
                <span className="text-xl">{f.icon}</span>
                <div>
                  <div className="text-sm font-medium text-gray-900 mb-0.5">{f.title}</div>
                  <div className="text-xs text-gray-500 leading-relaxed">{f.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

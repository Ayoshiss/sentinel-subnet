"use client";

import { useState } from "react";
import Link from "next/link";
import { Logo, EyeMark } from "@/components/brand";

type Step = "form" | "loading" | "done" | "error";

const API_HOST = "https://tao-gateway.fly.dev"; // swaps to api.bhairab.ai in Phase 2

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
    <div className="min-h-screen bg-[#0A0A0B] text-[#ECECEC] flex flex-col antialiased selection:bg-[#E5392B]/30">
      <header className="border-b border-[#1E1E20] px-6 h-16 flex items-center">
        <Link href="/"><Logo /></Link>
      </header>

      <div className="flex-1 flex">
        {/* Left: form */}
        <div className="flex-1 flex items-center justify-center px-6 py-12">
          <div className="w-full max-w-sm">

            {(step === "form" || step === "loading") && (
              <>
                <div className="mb-8">
                  <h1 className="text-2xl font-semibold tracking-tight mb-1">Create your account</h1>
                  <p className="text-sm text-[#8A8A8F]">Free to start. 100k tokens included. No card required.</p>
                </div>
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <label className="block text-xs font-medium text-[#8A8A8F] mb-1.5">Name</label>
                    <input
                      type="text"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="Ada Lovelace"
                      className="w-full bg-[#111113] border border-[#1E1E20] rounded-lg px-3.5 py-2.5 text-sm text-[#ECECEC] placeholder-[#55555B] focus:outline-none focus:border-[#E5392B]/50 transition"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-[#8A8A8F] mb-1.5">Work email</label>
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="ada@company.com"
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
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                        Creating account…
                      </span>
                    ) : "Create free account →"}
                  </button>
                </form>
                <p className="text-xs text-[#55555B] mt-4 text-center">
                  By signing up you agree to our <a href="#" className="underline hover:text-[#8A8A8F]">Terms of Service</a>.
                </p>
              </>
            )}

            {step === "done" && (
              <>
                <div className="flex items-center gap-2 mb-6">
                  <EyeMark size={22} />
                  <span className="text-sm font-medium text-[#ECECEC]">Account created</span>
                </div>

                <h1 className="text-2xl font-semibold tracking-tight mb-1">Your API key</h1>
                <p className="text-sm text-[#8A8A8F] mb-6">Copy and store this key, we won&apos;t show it again.</p>

                <div className="border border-[#1E1E20] rounded-lg mb-6 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-3 bg-[#111113] border-b border-[#1E1E20]">
                    <span className="text-xs font-medium text-[#8A8A8F] uppercase tracking-widest">API Key</span>
                    <button onClick={copyKey} className={`text-xs font-medium px-3 py-1 rounded-md transition-colors ${copied ? "bg-[#E5392B]/15 text-[#E5827B]" : "bg-[#0C0C0D] border border-[#1E1E20] text-[#8A8A8F] hover:border-[#33333A]"}`}>
                      {copied ? "✓ Copied" : "Copy"}
                    </button>
                  </div>
                  <div className="px-4 py-3">
                    <code className="text-xs text-[#B7B7BC] break-all leading-relaxed">{apiKey}</code>
                  </div>
                </div>

                <div className="border border-[#1E1E20] rounded-lg overflow-hidden mb-6">
                  <div className="bg-[#111113] border-b border-[#1E1E20] px-4 py-2.5 flex items-center gap-2">
                    <EyeMark size={13} />
                    <span className="text-xs text-[#8A8A8F] font-mono">quick start</span>
                  </div>
                  <pre className="px-4 py-3 text-xs font-mono text-[#B7B7BC] overflow-x-auto leading-relaxed bg-[#0C0C0D]">{`curl ${API_HOST}/v1/chat/completions \\
  -H "Authorization: Bearer ${apiKey.slice(0, 24)}..." \\
  -H "Content-Type: application/json" \\
  -d '{"model":"auto","messages":[
    {"role":"user","content":"Hello!"}
  ]}'`}</pre>
                </div>

                <Link href="/dashboard" className="block text-center w-full bg-[#E5392B] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#cf3325] transition-colors">
                  Go to dashboard →
                </Link>
              </>
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

        {/* Right: guardian panel */}
        <div className="hidden lg:flex w-96 bg-[#0C0C0D] border-l border-[#1E1E20] flex-col justify-center px-12 py-12">
          <EyeMark size={32} className="mb-8" />
          <h2 className="text-sm font-semibold text-[#ECECEC] mb-6 uppercase tracking-[0.2em]">What you get</h2>
          <div className="space-y-6">
            {[
              { title: "OpenAI-compatible", desc: "Change one URL. Your existing SDK works unchanged." },
              { title: "10× cheaper", desc: "Bittensor miners compete on price. You win." },
              { title: "Never down", desc: "Failover + backstop keep your app online when the network isn't." },
              { title: "Usage dashboard", desc: "Real-time token usage, cost, and routing data." },
            ].map((f) => (
              <div key={f.title} className="flex gap-3">
                <span className="text-[#E5392B] text-xs mt-1.5">◆</span>
                <div>
                  <div className="text-sm font-medium text-[#ECECEC] mb-0.5">{f.title}</div>
                  <div className="text-xs text-[#8A8A8F] leading-relaxed">{f.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

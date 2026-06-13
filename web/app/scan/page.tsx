"use client";

import { useState } from "react";
import Link from "next/link";
import { EyeMark, Logo } from "@/components/brand";

const API_HOST = "https://tao-gateway.fly.dev";
const DEMO_KEY = "sk_live_taogateway_dev";

const PRESETS = [
  { label: "SOL",     mint: "So11111111111111111111111111111111111111112" },
  { label: "BONK",   mint: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263" },
  { label: "USDC",   mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" },
  { label: "Unknown",mint: "1nvalidMintThatDoesNotExist1111111111111111" },
];

type Signals = {
  found: boolean; symbol?: string; name?: string;
  priceUsd: number; priceChange24hPct: number;
  liquidityUsd: number; volume24hUsd: number;
  ageDays: number; pairCount: number; topDex?: string;
  heuristics: string[]; source: string;
};

type ScanResult = {
  verdict: "proceed" | "caution" | "stop";
  confidence: number; summary: string; reasons: string[];
  signals: Signals; model: string; latencyMs: number;
  verdictSource: string; disclaimer: string;
};

const VERDICT = {
  proceed: { label: "PROCEED", icon: "✓", color: "text-[#4ade80]", border: "border-[#4ade80]/20", bg: "bg-[#4ade80]/5",  dot: "bg-[#4ade80]" },
  caution: { label: "CAUTION", icon: "⚠", color: "text-[#f59e0b]", border: "border-[#f59e0b]/20", bg: "bg-[#f59e0b]/5",  dot: "bg-[#f59e0b]" },
  stop:    { label: "STOP",    icon: "✕", color: "text-[#E5392B]", border: "border-[#E5392B]/20", bg: "bg-[#E5392B]/5",  dot: "bg-[#E5392B]" },
};

function fmt(n: number): string {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `$${(n / 1_000).toFixed(1)}K`;
  return `$${n.toFixed(2)}`;
}

// The verdict made physical: three lights. While scanning they chase in a loop
// (the guardian deciding); when the verdict lands, one locks on and glows.
function TrafficLight({ active, cycling = false, size = 13 }: {
  active?: "stop" | "caution" | "proceed" | null;
  cycling?: boolean;
  size?: number;
}) {
  const lights: Array<{ k: "stop" | "caution" | "proceed"; c: string }> = [
    { k: "stop",    c: "#E5392B" },
    { k: "caution", c: "#f59e0b" },
    { k: "proceed", c: "#4ade80" },
  ];
  return (
    <div className="flex flex-col items-center gap-2 border border-[#1E1E20] rounded-full px-2 py-2.5 bg-[#0A0A0B]">
      {lights.map((l, i) => {
        const on = active === l.k;
        return (
          <span
            key={l.k}
            className={cycling ? "tl-cycle" : ""}
            style={{
              width: size,
              height: size,
              borderRadius: "50%",
              background: l.c,
              opacity: cycling ? undefined : on ? 1 : 0.1,
              boxShadow: on && !cycling ? `0 0 10px ${l.c}, 0 0 22px ${l.c}55` : "none",
              animationDelay: cycling ? `${i * 0.35}s` : undefined,
              transition: "opacity 0.5s ease, box-shadow 0.5s ease",
            }}
          />
        );
      })}
      <style>{`
        @keyframes tlPulse { 0%, 100% { opacity: 0.1; } 30% { opacity: 1; } }
        .tl-cycle { animation: tlPulse 1.05s ease-in-out infinite; }
      `}</style>
    </div>
  );
}

function SignalRow({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-[#1E1E20] last:border-0">
      <span className="text-xs tracking-widest text-[#555] uppercase">{label}</span>
      <div className="text-right">
        <span className="text-sm font-medium text-[#ECECEC]">{value}</span>
        {sub && <span className="text-xs text-[#555] ml-2">{sub}</span>}
      </div>
    </div>
  );
}

export default function ScanPage() {
  const [token,   setToken]   = useState("");
  const [action,  setAction]  = useState("buy");
  const [amount,  setAmount]  = useState("500");
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState<ScanResult | null>(null);
  const [error,   setError]   = useState("");

  async function runScan(mint?: string) {
    const t = (mint ?? token).trim();
    if (!t) return;
    if (mint) setToken(mint);
    setLoading(true); setResult(null); setError("");
    try {
      const res  = await fetch(`${API_HOST}/v1/risk/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${DEMO_KEY}` },
        body: JSON.stringify({ chain: "solana", token: t, action, amountUsd: Number(amount) || 500 }),
      });
      const data = await res.json();
      if (!res.ok || !data.verdict) setError(data.error ?? "Scan failed — try again.");
      else setResult(data);
    } catch { setError("Could not reach the scanner. Check your connection."); }
    finally   { setLoading(false); }
  }

  const vc = result ? VERDICT[result.verdict] : null;

  return (
    <div className="min-h-screen bg-[#0A0A0B] text-[#ECECEC] antialiased">

      {/* Nav */}
      <header className="sticky top-0 z-50 bg-[#0A0A0B]/80 backdrop-blur border-b border-[#1E1E20]">
        <div className="max-w-5xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/"><Logo /></Link>
          <Link href="/dashboard" className="text-xs tracking-widest text-[#555] hover:text-[#ECECEC] transition-colors">
            DASHBOARD →
          </Link>
        </div>
      </header>

      <main className="max-w-2xl mx-auto px-6 pt-16 pb-24">

        {/* Hero */}
        <div className="flex flex-col items-center text-center mb-12">
          <div className="relative mb-6">
            <div className="absolute inset-0 blur-2xl bg-[#E5392B]/10 rounded-full scale-150" />
            <EyeMark size={52} className="relative z-10" />
          </div>
          <div className="inline-flex items-center gap-2 border border-[#1E1E20] rounded-full px-3 py-1 text-[10px] tracking-widest text-[#555] mb-5">
            <span className="w-1 h-1 rounded-full bg-[#E5392B]" />
            THE GUARDIAN
          </div>
          <h1 className="text-3xl font-semibold tracking-tight mb-3">
            Is it safe?
          </h1>
          <p className="text-sm text-[#555] leading-relaxed max-w-sm">
            Paste any Solana token. Bhairab checks the live market and answers in one word — before your money moves.
          </p>
        </div>

        {/* Scanner card */}
        <div className="border border-[#1E1E20] rounded-lg bg-[#0D0D0F] overflow-hidden mb-4">

          {/* Top bar */}
          <div className="flex items-center gap-2 px-4 py-3 border-b border-[#1E1E20] bg-[#0A0A0B]">
            <span className="w-2 h-2 rounded-full bg-[#E5392B]/60" />
            <span className="w-2 h-2 rounded-full bg-[#1E1E20]" />
            <span className="w-2 h-2 rounded-full bg-[#1E1E20]" />
            <span className="ml-2 text-[10px] tracking-widest text-[#333]">BHAIRAB / RISK / SCAN</span>
          </div>

          <div className="p-6 space-y-5">
            {/* Token input */}
            <div>
              <label className="block text-[10px] tracking-widest text-[#444] mb-2">TOKEN ADDRESS</label>
              <input
                value={token}
                onChange={(e) => setToken(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && runScan()}
                placeholder="e.g. So11111111111111111111111111111111111111112"
                className="w-full bg-[#0A0A0B] border border-[#1E1E20] rounded text-sm text-[#ECECEC] placeholder-[#333] px-3 py-2.5 outline-none focus:border-[#E5392B]/40 transition-colors font-mono"
              />
            </div>

            {/* Quick tokens */}
            <div className="flex gap-2 flex-wrap">
              {PRESETS.map((p) => (
                <button
                  key={p.label}
                  onClick={() => runScan(p.mint)}
                  className="text-[10px] tracking-widest px-3 py-1.5 rounded border border-[#1E1E20] text-[#444] hover:border-[#E5392B]/40 hover:text-[#ECECEC] transition-all"
                >
                  {p.label}
                </button>
              ))}
            </div>

            {/* Action + Amount */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] tracking-widest text-[#444] mb-2">ACTION</label>
                <select
                  value={action}
                  onChange={(e) => setAction(e.target.value)}
                  className="w-full bg-[#0A0A0B] border border-[#1E1E20] rounded text-sm text-[#ECECEC] px-3 py-2.5 outline-none focus:border-[#E5392B]/40 transition-colors"
                >
                  <option value="buy">Buy</option>
                  <option value="sell">Sell</option>
                  <option value="swap">Swap</option>
                  <option value="transfer">Transfer</option>
                </select>
              </div>
              <div>
                <label className="block text-[10px] tracking-widest text-[#444] mb-2">AMOUNT (USD)</label>
                <input
                  type="number"
                  value={amount}
                  onChange={(e) => setAmount(e.target.value)}
                  className="w-full bg-[#0A0A0B] border border-[#1E1E20] rounded text-sm text-[#ECECEC] px-3 py-2.5 outline-none focus:border-[#E5392B]/40 transition-colors font-mono"
                />
              </div>
            </div>

            {/* CTA */}
            <button
              onClick={() => runScan()}
              disabled={loading || !token.trim()}
              className={`w-full py-3 rounded text-xs font-semibold tracking-widest transition-all ${
                loading || !token.trim()
                  ? "bg-[#1E1E20] text-[#444] cursor-not-allowed"
                  : "bg-[#E5392B] text-white hover:bg-[#c72e22] cursor-pointer"
              }`}
            >
              {loading ? "ASKING…" : "ASK BHAIRAB"}
            </button>
          </div>
        </div>

        {/* Deciding — lights chase until the verdict lands */}
        {loading && (
          <div className="border border-[#1E1E20] rounded-lg bg-[#0D0D0F] p-8 flex flex-col items-center gap-4">
            <TrafficLight cycling />
            <p className="text-[10px] tracking-widest text-[#444]">LOOKING BOTH WAYS…</p>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="border border-[#E5392B]/20 bg-[#E5392B]/5 rounded-lg px-4 py-3 text-sm text-[#E5392B] mb-4">
            {error}
          </div>
        )}

        {/* Result */}
        {result && vc && (
          <div className="space-y-3">

            {/* Verdict */}
            <div className={`border ${vc.border} ${vc.bg} rounded-lg p-6`}>
              <div className="flex items-start gap-4">
                <div className="flex-shrink-0">
                  <TrafficLight active={result.verdict} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-1">
                    <span className={`text-xl font-bold tracking-wider ${vc.color}`}>{vc.label}</span>
                    <span className="text-[10px] tracking-widest text-[#444]">
                      {Math.round(result.confidence * 100)}% · {result.verdictSource.toUpperCase()} · {result.latencyMs}ms
                    </span>
                  </div>
                  <p className="text-sm text-[#ECECEC] leading-relaxed">{result.summary}</p>
                </div>
              </div>
            </div>

            {/* Reasons */}
            {result.reasons.length > 0 && (
              <div className="border border-[#1E1E20] rounded-lg bg-[#0D0D0F] overflow-hidden">
                <div className="px-4 py-3 border-b border-[#1E1E20]">
                  <span className="text-[10px] tracking-widest text-[#444]">REASONS</span>
                </div>
                <div className="px-4 py-1">
                  {result.reasons.map((r, i) => (
                    <div key={i} className="flex gap-3 py-2.5 border-b border-[#1E1E20] last:border-0">
                      <span className={`text-xs mt-0.5 flex-shrink-0 ${vc.color}`}>›</span>
                      <span className="text-sm text-[#ECECEC] leading-relaxed">{r}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Live signals */}
            {result.signals.found && (
              <div className="border border-[#1E1E20] rounded-lg bg-[#0D0D0F] overflow-hidden">
                <div className="px-4 py-3 border-b border-[#1E1E20] flex items-center justify-between">
                  <span className="text-[10px] tracking-widest text-[#444]">LIVE SIGNALS</span>
                  <span className="text-[10px] tracking-widest text-[#333]">
                    {result.signals.symbol && `${result.signals.symbol} · `}{result.signals.source.toUpperCase()}
                  </span>
                </div>
                <div className="px-4 py-1">
                  <SignalRow label="Price"     value={`$${result.signals.priceUsd < 0.001 ? result.signals.priceUsd.toExponential(2) : result.signals.priceUsd.toFixed(4)}`} />
                  <SignalRow
                    label="24h Change"
                    value={`${result.signals.priceChange24hPct > 0 ? "+" : ""}${result.signals.priceChange24hPct.toFixed(1)}%`}
                    sub={result.signals.priceChange24hPct > 10 ? "elevated" : result.signals.priceChange24hPct < -10 ? "declining" : "stable"}
                  />
                  <SignalRow label="Liquidity" value={fmt(result.signals.liquidityUsd)} />
                  <SignalRow label="24h Volume" value={fmt(result.signals.volume24hUsd)} />
                  <SignalRow label="Token Age" value={`${Math.round(result.signals.ageDays)} days`} />
                  <SignalRow label="Pairs"      value={String(result.signals.pairCount)} sub={result.signals.topDex ?? ""} />
                </div>
              </div>
            )}

            {/* Footer */}
            <p className="text-[10px] text-[#333] leading-relaxed px-1">
              {result.disclaimer} · Model: {result.model}
            </p>
          </div>
        )}

        {/* Empty state hint */}
        {!result && !loading && !error && (
          <div className="border border-dashed border-[#1E1E20] rounded-lg p-8 flex flex-col items-center gap-4">
            <TrafficLight active={null} />
            <p className="text-xs tracking-widest text-[#333]">ONE WORD. GREEN, YELLOW, OR RED.</p>
          </div>
        )}
      </main>
    </div>
  );
}

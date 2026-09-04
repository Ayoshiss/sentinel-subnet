"use client";

import { useState, useEffect, useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from "recharts";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Logo } from "@/components/brand";
import { AccountMenu } from "@/components/account-menu";

type UsageDay = { date: string; tokens: number; requests: number; cost: number };
type ApiKey = { id: string; prefix: string; name: string; last_used_at: string | null; requests: number };
type Tab = "tokens" | "requests" | "cost";

const API_HOST = "https://tao-gateway.fly.dev"; // swaps to api.bhairab.ai in Phase 2

const CREDIT_PACKS = [
  { name: "Starter", price: "$10", desc: "~20M tokens" },
  { name: "Builder", price: "$50", desc: "~100M tokens" },
  { name: "Scale", price: "$100", desc: "~200M tokens" },
];

function getCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp("(^| )" + name + "=([^;]+)"));
  return match ? match[2] : null;
}

// Pad sparse usage into a full 7-day window (zero-fill missing days) so the
// chart always renders as a line, not a single floating point.
function build7DaySeries(usage: UsageDay[]): UsageDay[] {
  const byDate = new Map(usage.map((u) => [u.date, u]));
  const out: UsageDay[] = [];
  const today = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(today.getDate() - i);
    const key = d.toISOString().slice(0, 10); // YYYY-MM-DD
    out.push(byDate.get(key) ?? { date: key, tokens: 0, requests: 0, cost: 0 });
  }
  return out;
}

function shortDate(date: string): string {
  const d = new Date(date + "T00:00:00");
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

export default function Dashboard() {
  const router = useRouter();
  const [usage, setUsage] = useState<UsageDay[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [email, setEmail] = useState("");
  const [tab, setTab] = useState<Tab>("tokens");
  const [loading, setLoading] = useState(true);
  const [balance, setBalance] = useState<number | null>(null);
  const [showTopUp, setShowTopUp] = useState(false);
  const [showNewKey, setShowNewKey] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [revoking, setRevoking] = useState<string | null>(null);

  const gatewayURL = process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";

  const fetchData = useCallback(async () => {
    const session = getCookie("session");
    if (!session) { router.push("/login"); return; }
    try {
      const payload = JSON.parse(atob(session.split(".")[1]));
      setEmail(payload.email ?? "");
    } catch {}

    const headers = { Authorization: `Bearer ${session}` };
    // cache: "no-store", these are live figures; never serve a stale cached copy
    const opts: RequestInit = { headers, cache: "no-store" };
    try {
      const [usageRes, keysRes, balanceRes] = await Promise.all([
        fetch(`${gatewayURL}/v1/usage`, opts),
        fetch(`${gatewayURL}/v1/keys`, opts),
        fetch(`${gatewayURL}/v1/billing/balance`, opts),
      ]);
      if (usageRes.status === 401 || keysRes.status === 401) { router.push("/login"); return; }
      const [usageData, keysData, balanceData] = await Promise.all([usageRes.json(), keysRes.json(), balanceRes.json()]);
      setUsage(usageData);
      setApiKeys(keysData);
      setBalance(balanceData.balance_usd ?? 0);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [gatewayURL, router]);

  useEffect(() => {
    fetchData();
    // Keep the dashboard live: poll every 20s, and refetch when the tab
    // regains focus, so usage/requests/last-used don't go stale.
    const interval = setInterval(fetchData, 20000);
    const onFocus = () => fetchData();
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onFocus);
    return () => {
      clearInterval(interval);
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onFocus);
    };
  }, [fetchData]);

  const totalTokens = usage.reduce((s, d) => s + d.tokens, 0);
  const totalRequests = usage.reduce((s, d) => s + d.requests, 0);
  const totalCost = usage.reduce((s, d) => s + d.cost, 0);
  const chartData = build7DaySeries(usage);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const formatter = (v: any) => {
    if (tab === "tokens") return [`${Number(v).toLocaleString()} tokens`, "Usage"];
    if (tab === "requests") return [`${v} requests`, "Requests"];
    return [`$${Number(v).toFixed(4)}`, "Cost"];
  };

  const yFormatter = (v: number | string) => {
    if (tab === "tokens") return `${(Number(v) / 1000).toFixed(0)}k`;
    if (tab === "cost") return `$${Number(v).toFixed(3)}`;
    return `${v}`;
  };

  async function buyCredits(packName: string) {
    const session = getCookie("session");
    if (!session) return;
    const res = await fetch(`${gatewayURL}/v1/billing/checkout`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${session}` },
      body: JSON.stringify({ pack: packName }),
    });
    if (res.ok) { const { url } = await res.json(); window.location.href = url; }
  }

  async function generateKey() {
    const session = getCookie("session");
    if (!session || !newKeyName) return;
    const payload = JSON.parse(atob(session.split(".")[1]));
    const adminSecret = process.env.NEXT_PUBLIC_ADMIN_SECRET ?? "";
    const custRes = await fetch(`${gatewayURL}/admin/keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Admin-Secret": adminSecret },
      body: JSON.stringify({ customer_id: payload.sub, name: newKeyName }),
    });
    if (custRes.ok) {
      const { key } = await custRes.json();
      alert(`Your new API key (save this, shown once):\n\n${key}`);
      setShowNewKey(false);
      setNewKeyName("");
      fetchData();
    }
  }

  async function revokeKey(id: string, name: string) {
    const session = getCookie("session");
    if (!session) return;
    if (!confirm(`Revoke "${name}"? Any app using this key will stop working immediately. This cannot be undone.`)) return;
    setRevoking(id);
    try {
      const res = await fetch(`${gatewayURL}/v1/keys/${id}`, { method: "DELETE", headers: { Authorization: `Bearer ${session}` } });
      if (res.ok) { setApiKeys((prev) => prev.filter((k) => k.id !== id)); fetchData(); }
      else if (res.status === 401) router.push("/login");
      else alert("Could not revoke key. Please try again.");
    } finally {
      setRevoking(null);
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0A0A0B] flex items-center justify-center">
        <svg className="animate-spin w-6 h-6 text-[#55555B]" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
          <path className="opacity-75" fill="#E5392B" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
        </svg>
      </div>
    );
  }

  const hasUsage = usage.length > 0;
  const card = "bg-[#0C0C0D] border border-[#1E1E20] rounded-xl";

  return (
    <div className="min-h-screen bg-[#0A0A0B] text-[#ECECEC] antialiased selection:bg-[#E5392B]/30">
      <header className="bg-[#0A0A0B]/80 backdrop-blur border-b border-[#1E1E20] sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/"><Logo /></Link>
          <AccountMenu email={email} />
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Dashboard</h1>
            <p className="text-sm text-[#8A8A8F] mt-0.5">Last 7 days</p>
          </div>
          <span className="flex items-center gap-1.5 text-xs text-[#8A8A8F] bg-[#0C0C0D] border border-[#1E1E20] px-3 py-1.5 rounded-lg">
            <span className="w-1.5 h-1.5 bg-[#E5392B] rounded-full" />
            SN64 Chutes · Healthy
          </span>
        </div>

        {/* Balance banner */}
        <div className={`flex items-center justify-between px-5 py-4 rounded-xl border mb-6 ${balance !== null && balance < 1 ? "bg-[#E5392B]/10 border-[#E5392B]/30" : card}`}>
          <div>
            <div className="text-xs font-medium text-[#8A8A8F] mb-0.5">Credit balance</div>
            <div className="text-2xl font-semibold">{balance !== null ? `$${balance.toFixed(4)}` : "—"}</div>
            {balance !== null && balance < 1 && (
              <div className="text-xs text-[#E5827B] mt-0.5">Low balance, top up to keep making requests</div>
            )}
          </div>
          <button onClick={() => setShowTopUp(!showTopUp)}
            className="bg-[#E5392B] text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-[#cf3325] transition-colors">
            + Add credits
          </button>
        </div>

        {/* Credit packs */}
        {showTopUp && (
          <div className="grid grid-cols-3 gap-4 mb-6">
            {CREDIT_PACKS.map((pack) => (
              <div key={pack.name} className={`${card} p-5 flex flex-col`}>
                <div className="text-xs font-medium text-[#8A8A8F] uppercase tracking-[0.2em] mb-1">{pack.name}</div>
                <div className="text-3xl font-semibold mb-0.5">{pack.price}</div>
                <div className="text-xs text-[#55555B] mb-4">{pack.desc}</div>
                <button onClick={() => buyCredits(pack.name)}
                  className="mt-auto bg-[#E5392B] text-white py-2 rounded-lg text-sm font-medium hover:bg-[#cf3325] transition-colors">
                  Buy {pack.price}
                </button>
              </div>
            ))}
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          {[
            { label: "Total tokens", value: totalTokens > 0 ? `${(totalTokens / 1000).toFixed(1)}k` : "0", sub: "this week" },
            { label: "Requests", value: totalRequests.toString(), sub: "this week" },
            { label: "Total cost", value: `$${totalCost.toFixed(4)}`, sub: "this week" },
            { label: "Avg latency", value: "~2s", sub: "p50 estimate" },
          ].map((stat) => (
            <div key={stat.label} className={`${card} p-5`}>
              <div className="text-xs font-medium text-[#8A8A8F] mb-3">{stat.label}</div>
              <div className="text-2xl font-semibold">{stat.value}</div>
              <div className="text-xs text-[#55555B] mt-1">{stat.sub}</div>
            </div>
          ))}
        </div>

        {/* Chart */}
        <div className={`${card} p-6 mb-6`}>
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-sm font-semibold">Usage over time</h2>
            <div className="flex bg-[#111113] border border-[#1E1E20] rounded-lg p-0.5 text-xs font-medium">
              {(["tokens", "requests", "cost"] as Tab[]).map((t) => (
                <button key={t} onClick={() => setTab(t)}
                  className={`px-3 py-1.5 rounded-md capitalize transition-colors ${tab === t ? "bg-[#1E1E20] text-[#ECECEC]" : "text-[#8A8A8F] hover:text-[#ECECEC]"}`}>
                  {t}
                </button>
              ))}
            </div>
          </div>

          {!hasUsage ? (
            <div className="h-[220px] flex items-center justify-center text-sm text-[#55555B]">
              No usage yet, make your first API call to see data here.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={chartData} margin={{ left: 0, right: 8 }} barCategoryGap="28%">
                <CartesianGrid strokeDasharray="3 3" stroke="#1E1E20" vertical={false}/>
                <XAxis dataKey="date" tickFormatter={shortDate} tick={{ fill: "#8A8A8F", fontSize: 11 }} axisLine={false} tickLine={false}/>
                <YAxis tick={{ fill: "#8A8A8F", fontSize: 11 }} axisLine={false} tickLine={false} tickFormatter={yFormatter} width={45} allowDecimals={false}/>
                <Tooltip
                  cursor={{ fill: "#FFFFFF06" }}
                  contentStyle={{ background: "#111113", border: "1px solid #1E1E20", borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: "#ECECEC", fontWeight: 600 }}
                  itemStyle={{ color: "#E5392B" }}
                  // eslint-disable-next-line @typescript-eslint/no-explicit-any
                  labelFormatter={(l: any) => shortDate(String(l))}
                  formatter={formatter}
                />
                <Bar dataKey={tab} radius={[3, 3, 0, 0]} maxBarSize={48}>
                  {chartData.map((d, i) => (
                    <Cell key={i} fill={d[tab] > 0 ? "#E5392B" : "#1E1E20"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* API Keys */}
        <div className={card}>
          <div className="flex items-center justify-between px-6 py-4 border-b border-[#1E1E20]">
            <h2 className="text-sm font-semibold">API Keys</h2>
            <button onClick={() => setShowNewKey(!showNewKey)}
              className="text-xs bg-[#E5392B] text-white px-3 py-1.5 rounded-lg font-medium hover:bg-[#cf3325] transition-colors">
              + New key
            </button>
          </div>

          {showNewKey && (
            <div className="px-6 py-4 border-b border-[#1E1E20] bg-[#111113]">
              <p className="text-xs font-medium text-[#8A8A8F] mb-2">Key name</p>
              <div className="flex gap-2">
                <input type="text" value={newKeyName} onChange={(e) => setNewKeyName(e.target.value)}
                  placeholder="e.g. production"
                  className="flex-1 bg-[#0C0C0D] border border-[#1E1E20] rounded-lg px-3 py-2 text-sm text-[#ECECEC] placeholder-[#55555B] focus:outline-none focus:border-[#E5392B]/50"/>
                <button onClick={generateKey} disabled={!newKeyName}
                  className="bg-[#E5392B] text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-[#cf3325] disabled:opacity-40 transition-colors">
                  Generate
                </button>
                <button onClick={() => setShowNewKey(false)} className="text-sm text-[#8A8A8F] px-2 hover:text-[#ECECEC]">Cancel</button>
              </div>
            </div>
          )}

          <div className="divide-y divide-[#1E1E20]">
            {apiKeys.length === 0 ? (
              <div className="px-6 py-8 text-sm text-[#55555B] text-center">No API keys yet.</div>
            ) : apiKeys.map((key) => (
              <div key={key.id} className="flex items-center justify-between px-6 py-4">
                <div className="flex items-center gap-4">
                  <div className="w-8 h-8 bg-[#111113] border border-[#1E1E20] rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-[#8A8A8F]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
                    </svg>
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <code className="text-sm font-mono text-[#ECECEC]">{key.prefix}••••••••</code>
                      <span className="text-xs bg-[#E5392B]/10 text-[#E5827B] border border-[#E5392B]/30 px-2 py-0.5 rounded-full font-medium">Active</span>
                    </div>
                    <div className="text-xs text-[#55555B] mt-0.5">
                      {key.name} · {key.last_used_at ? `Last used ${new Date(key.last_used_at).toLocaleDateString()}` : "Never used"}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-5 text-sm">
                  <span className="text-[#8A8A8F] text-xs">{key.requests.toLocaleString()} requests</span>
                  <button onClick={() => revokeKey(key.id, key.name)} disabled={revoking === key.id}
                    className="text-xs font-medium text-[#E5827B] hover:text-[#E5392B] disabled:opacity-40 transition-colors">
                    {revoking === key.id ? "Revoking…" : "Revoke"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Quick start */}
        <div className={`mt-6 ${card} p-6`}>
          <h2 className="text-sm font-semibold mb-4">Quick start</h2>
          <div className="grid md:grid-cols-2 gap-4">
            {[
              { lang: "python", code: `from openai import OpenAI\n\nclient = OpenAI(\n  api_key="sk_live_...",\n  base_url="${API_HOST}/v1"\n)\n\nresp = client.chat.completions.create(\n  model="auto",\n  messages=[{"role":"user","content":"Hello!"}]\n)` },
              { lang: "cURL", code: `curl ${API_HOST}/v1/chat/completions \\\n  -H "Authorization: Bearer sk_live_..." \\\n  -H "Content-Type: application/json" \\\n  -d '{"model":"auto","messages":[{"role":"user","content":"Hello!"}]}'` }
            ].map((s) => (
              <div key={s.lang} className="border border-[#1E1E20] rounded-lg overflow-hidden">
                <div className="bg-[#111113] border-b border-[#1E1E20] px-4 py-2 flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#E5392B]" />
                  <span className="text-xs text-[#8A8A8F] font-mono">{s.lang}</span>
                </div>
                <pre className="p-4 text-xs font-mono text-[#B7B7BC] overflow-x-auto leading-relaxed bg-[#0C0C0D]">{s.code}</pre>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

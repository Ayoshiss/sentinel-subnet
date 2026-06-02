"use client";

import { useState, useEffect, useCallback } from "react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import Link from "next/link";
import { useRouter } from "next/navigation";

type UsageDay = { date: string; tokens: number; requests: number; cost: number };
type ApiKey = { id: string; prefix: string; name: string; last_used_at: string | null; requests: number };
type Tab = "tokens" | "requests" | "cost";

const CREDIT_PACKS = [
  { name: "Starter", price: "$10", credits: "$10", desc: "~20M tokens" },
  { name: "Builder", price: "$50", credits: "$50", desc: "~100M tokens" },
  { name: "Scale",   price: "$100", credits: "$100", desc: "~200M tokens" },
];

function getCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp("(^| )" + name + "=([^;]+)"));
  return match ? match[2] : null;
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

    // Decode email from JWT (no verify needed — just display)
    try {
      const payload = JSON.parse(atob(session.split(".")[1]));
      setEmail(payload.email ?? "");
    } catch {}

    const headers = { Authorization: `Bearer ${session}` };

    try {
      const [usageRes, keysRes, balanceRes] = await Promise.all([
        fetch(`${gatewayURL}/v1/usage`, { headers }),
        fetch(`${gatewayURL}/v1/keys`, { headers }),
        fetch(`${gatewayURL}/v1/billing/balance`, { headers }),
      ]);

      if (usageRes.status === 401 || keysRes.status === 401) {
        router.push("/login");
        return;
      }

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

  useEffect(() => { fetchData(); }, [fetchData]);

  const totalTokens = usage.reduce((s, d) => s + d.tokens, 0);
  const totalRequests = usage.reduce((s, d) => s + d.requests, 0);
  const totalCost = usage.reduce((s, d) => s + d.cost, 0);

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
    if (res.ok) {
      const { url } = await res.json();
      window.location.href = url;
    }
  }

  async function generateKey() {
    const session = getCookie("session");
    if (!session || !newKeyName) return;
    const payload = JSON.parse(atob(session.split(".")[1]));
    const adminSecret = process.env.NEXT_PUBLIC_ADMIN_SECRET ?? "";

    // Create key for this customer
    const custRes = await fetch(`${gatewayURL}/admin/keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Admin-Secret": adminSecret },
      body: JSON.stringify({ customer_id: payload.sub, name: newKeyName }),
    });
    if (custRes.ok) {
      const { key } = await custRes.json();
      alert(`Your new API key (save this — shown once):\n\n${key}`);
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
      const res = await fetch(`${gatewayURL}/v1/keys/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${session}` },
      });
      if (res.ok) {
        // Optimistically drop it from the list, then refresh from server
        setApiKeys((prev) => prev.filter((k) => k.id !== id));
        fetchData();
      } else if (res.status === 401) {
        router.push("/login");
      } else {
        alert("Could not revoke key. Please try again.");
      }
    } finally {
      setRevoking(null);
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <svg className="animate-spin w-6 h-6 text-gray-400" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
        </svg>
      </div>
    );
  }

  const hasUsage = usage.length > 0;

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white border-b border-gray-200 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between">
          <Link href="/" className="font-semibold text-gray-900 tracking-tight">TAO Gateway</Link>
          <div className="flex items-center gap-3">
            {email && <span className="text-xs text-gray-500 hidden sm:block">{email}</span>}
            <div className="w-8 h-8 bg-gray-900 rounded-full flex items-center justify-center text-white text-xs font-semibold">
              {email ? email[0].toUpperCase() : "?"}
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-xl font-bold text-gray-900">Dashboard</h1>
            <p className="text-sm text-gray-500 mt-0.5">Last 7 days</p>
          </div>
          <span className="flex items-center gap-1.5 text-xs text-gray-500 bg-white border border-gray-200 px-3 py-1.5 rounded-lg">
            <span className="w-1.5 h-1.5 bg-green-500 rounded-full" />
            SN64 Chutes · Healthy
          </span>
        </div>

        {/* Balance banner */}
        <div className={`flex items-center justify-between px-5 py-4 rounded-xl border mb-6 ${balance !== null && balance < 1 ? "bg-red-50 border-red-200" : "bg-white border-gray-200"}`}>
          <div>
            <div className="text-xs font-medium text-gray-500 mb-0.5">Credit balance</div>
            <div className="text-2xl font-bold text-gray-900">
              {balance !== null ? `$${balance.toFixed(4)}` : "—"}
            </div>
            {balance !== null && balance < 1 && (
              <div className="text-xs text-red-600 mt-0.5">Low balance — top up to keep making requests</div>
            )}
          </div>
          <button
            onClick={() => setShowTopUp(!showTopUp)}
            className="bg-gray-900 text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-gray-700 transition-colors"
          >
            + Add credits
          </button>
        </div>

        {/* Credit packs */}
        {showTopUp && (
          <div className="grid grid-cols-3 gap-4 mb-6">
            {CREDIT_PACKS.map((pack) => (
              <div key={pack.name} className="bg-white border border-gray-200 rounded-xl p-5 flex flex-col">
                <div className="text-xs font-medium text-gray-400 uppercase tracking-widest mb-1">{pack.name}</div>
                <div className="text-3xl font-bold text-gray-900 mb-0.5">{pack.price}</div>
                <div className="text-xs text-gray-400 mb-4">{pack.desc}</div>
                <button
                  onClick={() => buyCredits(pack.name)}
                  className="mt-auto bg-gray-900 text-white py-2 rounded-lg text-sm font-medium hover:bg-gray-700 transition-colors"
                >
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
            <div key={stat.label} className="bg-white border border-gray-200 rounded-xl p-5">
              <div className="text-xs font-medium text-gray-500 mb-3">{stat.label}</div>
              <div className="text-2xl font-bold text-gray-900">{stat.value}</div>
              <div className="text-xs text-gray-400 mt-1">{stat.sub}</div>
            </div>
          ))}
        </div>

        {/* Chart */}
        <div className="bg-white border border-gray-200 rounded-xl p-6 mb-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-sm font-semibold text-gray-900">Usage over time</h2>
            <div className="flex bg-gray-100 rounded-lg p-0.5 text-xs font-medium">
              {(["tokens", "requests", "cost"] as Tab[]).map((t) => (
                <button key={t} onClick={() => setTab(t)}
                  className={`px-3 py-1.5 rounded-md capitalize transition-colors ${tab === t ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                  {t}
                </button>
              ))}
            </div>
          </div>

          {!hasUsage ? (
            <div className="h-[220px] flex items-center justify-center text-sm text-gray-400">
              No usage yet — make your first API call to see data here.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={usage} margin={{ left: 0, right: 0 }}>
                <defs>
                  <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#111827" stopOpacity={0.08}/>
                    <stop offset="100%" stopColor="#111827" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6"/>
                <XAxis dataKey="date" tick={{ fill: "#9ca3af", fontSize: 11 }} axisLine={false} tickLine={false}/>
                <YAxis tick={{ fill: "#9ca3af", fontSize: 11 }} axisLine={false} tickLine={false} tickFormatter={yFormatter} width={45}/>
                <Tooltip
                  contentStyle={{ background: "#fff", border: "1px solid #e5e7eb", borderRadius: 8, fontSize: 12, boxShadow: "0 4px 6px -1px rgba(0,0,0,0.1)" }}
                  labelStyle={{ color: "#374151", fontWeight: 600 }}
                  formatter={formatter}
                />
                <Area type="monotone" dataKey={tab} stroke="#111827" strokeWidth={2} fill="url(#grad)" dot={false}/>
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* API Keys */}
        <div className="bg-white border border-gray-200 rounded-xl">
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
            <h2 className="text-sm font-semibold text-gray-900">API Keys</h2>
            <button onClick={() => setShowNewKey(!showNewKey)}
              className="text-xs bg-gray-900 text-white px-3 py-1.5 rounded-lg font-medium hover:bg-gray-700 transition-colors">
              + New key
            </button>
          </div>

          {showNewKey && (
            <div className="px-6 py-4 border-b border-gray-100 bg-gray-50">
              <p className="text-xs font-medium text-gray-700 mb-2">Key name</p>
              <div className="flex gap-2">
                <input type="text" value={newKeyName} onChange={(e) => setNewKeyName(e.target.value)}
                  placeholder="e.g. production"
                  className="flex-1 border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-900"/>
                <button onClick={generateKey} disabled={!newKeyName}
                  className="bg-gray-900 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-700 disabled:opacity-40 transition-colors">
                  Generate
                </button>
                <button onClick={() => setShowNewKey(false)} className="text-sm text-gray-500 px-2">Cancel</button>
              </div>
            </div>
          )}

          <div className="divide-y divide-gray-50">
            {apiKeys.length === 0 ? (
              <div className="px-6 py-8 text-sm text-gray-400 text-center">No API keys yet.</div>
            ) : apiKeys.map((key) => (
              <div key={key.id} className="flex items-center justify-between px-6 py-4">
                <div className="flex items-center gap-4">
                  <div className="w-8 h-8 bg-gray-100 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
                    </svg>
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <code className="text-sm font-mono text-gray-900">{key.prefix}••••••••</code>
                      <span className="text-xs bg-green-50 text-green-700 border border-green-200 px-2 py-0.5 rounded-full font-medium">Active</span>
                    </div>
                    <div className="text-xs text-gray-400 mt-0.5">
                      {key.name} · {key.last_used_at ? `Last used ${new Date(key.last_used_at).toLocaleDateString()}` : "Never used"}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-5 text-sm">
                  <span className="text-gray-500 text-xs">{key.requests.toLocaleString()} requests</span>
                  <button
                    onClick={() => revokeKey(key.id, key.name)}
                    disabled={revoking === key.id}
                    className="text-xs font-medium text-red-500 hover:text-red-700 disabled:opacity-40 transition-colors"
                  >
                    {revoking === key.id ? "Revoking…" : "Revoke"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Quick start */}
        <div className="mt-6 bg-white border border-gray-200 rounded-xl p-6">
          <h2 className="text-sm font-semibold text-gray-900 mb-4">Quick start</h2>
          <div className="grid md:grid-cols-2 gap-4">
            {[
              { lang: "Python", code: `from openai import OpenAI\n\nclient = OpenAI(\n  api_key="sk_live_...",\n  base_url="https://tao-gateway.fly.dev/v1"\n)\n\nresp = client.chat.completions.create(\n  model="gpt-4o",\n  messages=[{"role":"user","content":"Hello!"}]\n)` },
              { lang: "cURL", code: `curl https://tao-gateway.fly.dev/v1/chat/completions \\\n  -H "Authorization: Bearer sk_live_..." \\\n  -H "Content-Type: application/json" \\\n  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Hello!"}]}'` }
            ].map((s) => (
              <div key={s.lang} className="border border-gray-200 rounded-lg overflow-hidden">
                <div className="bg-gray-50 border-b border-gray-200 px-4 py-2 flex items-center gap-2">
                  <div className="flex gap-1">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-400"/>
                    <span className="w-2.5 h-2.5 rounded-full bg-yellow-400"/>
                    <span className="w-2.5 h-2.5 rounded-full bg-green-400"/>
                  </div>
                  <span className="text-xs text-gray-400 font-mono">{s.lang}</span>
                </div>
                <pre className="p-4 text-xs font-mono text-gray-600 overflow-x-auto leading-relaxed bg-white">{s.code}</pre>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

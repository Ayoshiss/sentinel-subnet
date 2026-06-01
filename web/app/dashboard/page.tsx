"use client";

import { useState } from "react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import Link from "next/link";

const MOCK_USAGE = [
  { date: "May 25", tokens: 12400, requests: 24, cost: 0.018 },
  { date: "May 26", tokens: 34200, requests: 67, cost: 0.051 },
  { date: "May 27", tokens: 28900, requests: 52, cost: 0.043 },
  { date: "May 28", tokens: 51200, requests: 98, cost: 0.077 },
  { date: "May 29", tokens: 43800, requests: 81, cost: 0.066 },
  { date: "May 30", tokens: 67100, requests: 124, cost: 0.100 },
  { date: "May 31", tokens: 41200, requests: 76, cost: 0.062 },
];

const MOCK_KEYS = [
  { id: "1", prefix: "sk_live_tao", name: "default", lastUsed: "2 minutes ago", requests: 522, active: true },
];

type Tab = "tokens" | "requests" | "cost";

export default function Dashboard() {
  const [tab, setTab] = useState<Tab>("tokens");
  const [showNewKey, setShowNewKey] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");

  const totalTokens = MOCK_USAGE.reduce((s, d) => s + d.tokens, 0);
  const totalRequests = MOCK_USAGE.reduce((s, d) => s + d.requests, 0);
  const totalCost = MOCK_USAGE.reduce((s, d) => s + d.cost, 0);

  const dataKey = tab;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const formatter = (v: any) => {
    if (tab === "tokens") return [`${Number(v).toLocaleString()} tokens`, "Usage"];
    if (tab === "requests") return [`${v} requests`, "Requests"];
    return [`$${Number(v).toFixed(4)}`, "Cost"];
  };

  const yFormatter = tab === "tokens"
    ? (v: number | string) => `${(Number(v) / 1000).toFixed(0)}k`
    : tab === "cost"
    ? (v: number | string) => `$${Number(v).toFixed(2)}`
    : (v: number | string) => `${v}`;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Nav */}
      <header className="bg-white border-b border-gray-200 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between">
          <Link href="/" className="font-semibold text-gray-900 tracking-tight">TAO Gateway</Link>
          <div className="flex items-center gap-3">
            <span className="text-xs bg-gray-100 text-gray-600 px-2.5 py-1 rounded-full font-medium">Free plan</span>
            <div className="w-8 h-8 bg-gray-900 rounded-full flex items-center justify-center text-white text-xs font-semibold">D</div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">

        {/* Page header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-xl font-bold text-gray-900">Dashboard</h1>
            <p className="text-sm text-gray-500 mt-0.5">Last 7 days</p>
          </div>
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 text-xs text-gray-500 bg-white border border-gray-200 px-3 py-1.5 rounded-lg">
              <span className="w-1.5 h-1.5 bg-green-500 rounded-full" />
              SN64 Chutes · Healthy
            </span>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          {[
            { label: "Total tokens", value: `${(totalTokens / 1000).toFixed(1)}k`, sub: "this week", delta: "+12%" },
            { label: "Requests", value: totalRequests.toString(), sub: "this week", delta: "+8%" },
            { label: "Total cost", value: `$${totalCost.toFixed(2)}`, sub: "this week", delta: null },
            { label: "Avg latency", value: "1.8s", sub: "p50", delta: null },
          ].map((stat) => (
            <div key={stat.label} className="bg-white border border-gray-200 rounded-xl p-5">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-medium text-gray-500">{stat.label}</span>
                {stat.delta && <span className="text-xs font-medium text-green-600 bg-green-50 px-2 py-0.5 rounded-full">{stat.delta}</span>}
              </div>
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
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`px-3 py-1.5 rounded-md capitalize transition-colors ${tab === t ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={MOCK_USAGE} margin={{ left: 0, right: 0 }}>
              <defs>
                <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#111827" stopOpacity={0.08} />
                  <stop offset="100%" stopColor="#111827" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
              <XAxis dataKey="date" tick={{ fill: "#9ca3af", fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#9ca3af", fontSize: 11 }} axisLine={false} tickLine={false} tickFormatter={yFormatter} width={40} />
              <Tooltip
                contentStyle={{ background: "#fff", border: "1px solid #e5e7eb", borderRadius: 8, fontSize: 12, boxShadow: "0 4px 6px -1px rgba(0,0,0,0.1)" }}
                labelStyle={{ color: "#374151", fontWeight: 600 }}
                formatter={formatter}
              />
              <Area type="monotone" dataKey={dataKey} stroke="#111827" strokeWidth={2} fill="url(#grad)" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* API Keys */}
        <div className="bg-white border border-gray-200 rounded-xl">
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
            <h2 className="text-sm font-semibold text-gray-900">API Keys</h2>
            <button
              onClick={() => setShowNewKey(!showNewKey)}
              className="text-xs bg-gray-900 text-white px-3 py-1.5 rounded-lg font-medium hover:bg-gray-700 transition-colors"
            >
              + New key
            </button>
          </div>

          {showNewKey && (
            <div className="px-6 py-4 border-b border-gray-100 bg-gray-50">
              <p className="text-xs font-medium text-gray-700 mb-2">Key name</p>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  placeholder="e.g. production"
                  className="flex-1 border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-900 focus:border-transparent"
                />
                <button className="bg-gray-900 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-700 transition-colors">Generate</button>
                <button onClick={() => setShowNewKey(false)} className="text-sm text-gray-500 px-2 hover:text-gray-700">Cancel</button>
              </div>
            </div>
          )}

          <div className="divide-y divide-gray-50">
            {MOCK_KEYS.map((key) => (
              <div key={key.id} className="flex items-center justify-between px-6 py-4">
                <div className="flex items-center gap-4">
                  <div className="w-8 h-8 bg-gray-100 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                    </svg>
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <code className="text-sm font-mono text-gray-900">{key.prefix}••••••••</code>
                      <span className="text-xs bg-green-50 text-green-700 border border-green-200 px-2 py-0.5 rounded-full font-medium">Active</span>
                    </div>
                    <div className="text-xs text-gray-400 mt-0.5">{key.name} · Last used {key.lastUsed}</div>
                  </div>
                </div>
                <div className="flex items-center gap-6 text-sm">
                  <span className="text-gray-500 text-xs">{key.requests.toLocaleString()} requests</span>
                  <button className="text-xs text-red-500 hover:text-red-700 font-medium transition-colors">Revoke</button>
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
              { lang: "Python", code: `from openai import OpenAI

client = OpenAI(
  api_key="sk_live_...",
  base_url="https://api.taogateway.dev/v1"
)

resp = client.chat.completions.create(
  model="gpt-4o",
  messages=[{"role":"user","content":"Hello!"}]
)` },
              { lang: "cURL", code: `curl https://api.taogateway.dev/v1/chat/completions \\
  -H "Authorization: Bearer sk_live_..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "gpt-4o",
    "messages": [
      {"role": "user", "content": "Hello!"}
    ]
  }'` }
            ].map((s) => (
              <div key={s.lang} className="border border-gray-200 rounded-lg overflow-hidden">
                <div className="bg-gray-50 border-b border-gray-200 px-4 py-2 flex items-center gap-2">
                  <div className="flex gap-1">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-400" />
                    <span className="w-2.5 h-2.5 rounded-full bg-yellow-400" />
                    <span className="w-2.5 h-2.5 rounded-full bg-green-400" />
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

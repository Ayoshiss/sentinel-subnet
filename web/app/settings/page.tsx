"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Logo } from "@/components/brand";
import { AccountMenu, logout } from "@/components/account-menu";

type Purchase = { amount_usd: number; credits_usd: number; status: string; created_at: string; paid_at: string | null };

const CREDIT_PACKS = [
  { name: "Starter", price: "$10", desc: "~20M tokens" },
  { name: "Builder", price: "$50", desc: "~100M tokens" },
  { name: "Scale", price: "$100", desc: "~200M tokens" },
];

function getCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const m = document.cookie.match(new RegExp("(^| )" + name + "=([^;]+)"));
  return m ? m[2] : null;
}

function fmtDate(s: string) {
  return new Date(s).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

export default function Settings() {
  const router = useRouter();
  const gatewayURL = process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";

  const [loading, setLoading] = useState(true);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [createdAt, setCreatedAt] = useState("");
  const [balance, setBalance] = useState<number | null>(null);
  const [history, setHistory] = useState<Purchase[]>([]);
  const [savingName, setSavingName] = useState(false);
  const [savedName, setSavedName] = useState(false);
  const [portalLoading, setPortalLoading] = useState(false);

  const session = typeof window !== "undefined" ? getCookie("session") : null;

  const fetchAll = useCallback(async () => {
    if (!session) { router.push("/login"); return; }
    const opts: RequestInit = { headers: { Authorization: `Bearer ${session}` }, cache: "no-store" };
    try {
      const [acc, bal, hist] = await Promise.all([
        fetch(`${gatewayURL}/v1/account`, opts),
        fetch(`${gatewayURL}/v1/billing/balance`, opts),
        fetch(`${gatewayURL}/v1/billing/history`, opts),
      ]);
      if (acc.status === 401) { router.push("/login"); return; }
      const accData = await acc.json();
      setEmail(accData.email ?? "");
      setName(accData.name ?? "");
      setCreatedAt(accData.created_at ?? "");
      setBalance((await bal.json()).balance_usd ?? 0);
      setHistory(await hist.json());
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [gatewayURL, router, session]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  async function saveName() {
    if (!session) return;
    setSavingName(true);
    setSavedName(false);
    try {
      const res = await fetch(`${gatewayURL}/v1/account`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${session}` },
        body: JSON.stringify({ name }),
      });
      if (res.ok) { setSavedName(true); setTimeout(() => setSavedName(false), 2000); }
    } finally {
      setSavingName(false);
    }
  }

  async function buyCredits(pack: string) {
    if (!session) return;
    const res = await fetch(`${gatewayURL}/v1/billing/checkout`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${session}` },
      body: JSON.stringify({ pack }),
    });
    if (res.ok) { window.location.href = (await res.json()).url; }
  }

  async function openPortal() {
    if (!session) return;
    setPortalLoading(true);
    try {
      const res = await fetch(`${gatewayURL}/v1/billing/portal`, {
        method: "POST",
        headers: { Authorization: `Bearer ${session}` },
      });
      if (res.ok) { window.location.href = (await res.json()).url; }
      else { alert("Billing portal isn't available yet. (Enable the Stripe Customer Portal in test settings.)"); }
    } finally {
      setPortalLoading(false);
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

  const card = "bg-[#0C0C0D] border border-[#1E1E20] rounded-xl";

  return (
    <div className="min-h-screen bg-[#0A0A0B] text-[#ECECEC] antialiased selection:bg-[#E5392B]/30">
      <header className="bg-[#0A0A0B]/80 backdrop-blur border-b border-[#1E1E20] sticky top-0 z-10">
        <div className="max-w-3xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/"><Logo /></Link>
          <AccountMenu email={email} />
        </div>
      </header>

      <div className="max-w-3xl mx-auto px-6 py-10">
        <h1 className="text-xl font-semibold tracking-tight mb-1">Settings</h1>
        <p className="text-sm text-[#8A8A8F] mb-8">Manage your account and billing.</p>

        {/* Account */}
        <section className={`${card} p-6 mb-6`}>
          <h2 className="text-sm font-semibold uppercase tracking-[0.2em] text-[#8A8A8F] mb-5">Account</h2>

          <div className="space-y-5">
            <div>
              <label className="block text-xs font-medium text-[#8A8A8F] mb-1.5">Display name</label>
              <div className="flex gap-2 max-w-md">
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Your name"
                  className="flex-1 bg-[#111113] border border-[#1E1E20] rounded-lg px-3.5 py-2.5 text-sm text-[#ECECEC] placeholder-[#55555B] focus:outline-none focus:border-[#E5392B]/50 transition"
                />
                <button onClick={saveName} disabled={savingName}
                  className="px-4 py-2.5 rounded-lg text-sm font-medium bg-[#E5392B] text-white hover:bg-[#cf3325] disabled:opacity-40 transition-colors">
                  {savingName ? "Saving…" : savedName ? "✓ Saved" : "Save"}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#8A8A8F] mb-1.5">Email</label>
              <div className="text-sm text-[#ECECEC]">{email}</div>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#8A8A8F] mb-1.5">Member since</label>
              <div className="text-sm text-[#ECECEC]">{createdAt ? fmtDate(createdAt) : "—"}</div>
            </div>

            <div className="pt-2 border-t border-[#1E1E20]">
              <button onClick={() => logout(router)} className="text-sm font-medium text-[#E5827B] hover:text-[#E5392B] transition-colors">
                Log out
              </button>
            </div>
          </div>
        </section>

        {/* Billing */}
        <section className={`${card} p-6`}>
          <h2 className="text-sm font-semibold uppercase tracking-[0.2em] text-[#8A8A8F] mb-5">Billing</h2>

          {/* Balance */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <div className="text-xs text-[#8A8A8F] mb-0.5">Credit balance</div>
              <div className="text-2xl font-semibold">{balance !== null ? `$${balance.toFixed(4)}` : "—"}</div>
            </div>
            <button onClick={openPortal} disabled={portalLoading}
              className="text-sm font-medium border border-[#1E1E20] text-[#ECECEC] px-4 py-2 rounded-lg hover:border-[#33333A] disabled:opacity-40 transition-colors">
              {portalLoading ? "Opening…" : "Manage payment & receipts"}
            </button>
          </div>

          {/* Credit packs */}
          <div className="grid grid-cols-3 gap-3 mb-6">
            {CREDIT_PACKS.map((p) => (
              <div key={p.name} className="border border-[#1E1E20] rounded-lg p-4 flex flex-col">
                <div className="text-xs text-[#8A8A8F] uppercase tracking-widest mb-1">{p.name}</div>
                <div className="text-2xl font-semibold mb-0.5">{p.price}</div>
                <div className="text-xs text-[#55555B] mb-3">{p.desc}</div>
                <button onClick={() => buyCredits(p.name)}
                  className="mt-auto bg-[#E5392B] text-white py-1.5 rounded-lg text-sm font-medium hover:bg-[#cf3325] transition-colors">
                  Buy {p.price}
                </button>
              </div>
            ))}
          </div>

          {/* Purchase history */}
          <div>
            <div className="text-xs font-medium text-[#8A8A8F] mb-2">Purchase history</div>
            {history.length === 0 ? (
              <div className="text-sm text-[#55555B] py-4 text-center border border-[#1E1E20] rounded-lg">No purchases yet.</div>
            ) : (
              <div className="border border-[#1E1E20] rounded-lg overflow-hidden divide-y divide-[#1E1E20]">
                {history.map((p, i) => (
                  <div key={i} className="flex items-center justify-between px-4 py-3 text-sm">
                    <div>
                      <span className="text-[#ECECEC]">${p.amount_usd.toFixed(2)}</span>
                      <span className="text-[#55555B] ml-2 text-xs">{fmtDate(p.created_at)}</span>
                    </div>
                    <span className={`text-xs px-2 py-0.5 rounded-full border ${
                      p.status === "paid"
                        ? "bg-[#E5392B]/10 text-[#E5827B] border-[#E5392B]/30"
                        : "bg-[#111113] text-[#8A8A8F] border-[#1E1E20]"
                    }`}>
                      {p.status}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}

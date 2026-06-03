import Link from "next/link";
import { EyeMark, Logo } from "@/components/brand";
import { AuthNav, HeroCTA } from "@/components/auth-nav";

const API_HOST = "https://tao-gateway.fly.dev"; // swaps to api.bhairab.ai in Phase 2

const COMPARISON = [
  { label: "GPT-4o", provider: "OpenAI", input: "$5.00", output: "$15.00", us: false },
  { label: "Claude Sonnet", provider: "Anthropic", input: "$3.00", output: "$15.00", us: false },
  { label: "Bhairab", provider: "Bittensor SN64", input: "$0.50", output: "$1.50", us: true },
];

const PILLARS = [
  {
    k: "01",
    title: "10× cheaper",
    body: "Inference runs on Bittensor's decentralized GPU network — no data-center markup, no brand premium. You pay a fraction of OpenAI's rate.",
  },
  {
    k: "02",
    title: "Never down",
    body: "Decentralized nodes are chaotic. Bhairab guards against it — a sub-5s failover ladder and an invisible backstop keep your app online when the network isn't.",
  },
  {
    k: "03",
    title: "No crypto",
    body: "Pay with a credit card. No wallet, no TAO, no staking, no Subtensor node. The entire decentralized machinery stays invisible.",
  },
];

const STEPS = [
  { n: "1", t: "Get a key", d: "Sign up with an email. 100k tokens free, no card." },
  { n: "2", t: "Change one line", d: "Point your OpenAI SDK at our endpoint. Nothing else changes." },
  { n: "3", t: "We guard the rest", d: "Routing, failover, paying miners in TAO, fiat billing — handled." },
];

const PRICING = [
  { name: "Free", price: "$0", period: "", desc: "Try it", features: ["100k tokens", "SN64 access", "Community support"], cta: "Get started", href: "/signup", hl: false },
  { name: "Builder", price: "$29", period: "/mo", desc: "For production", features: ["10M tokens", "Smart routing", "Failover backstop", "Usage dashboard"], cta: "Start building", href: "/signup", hl: true },
  { name: "Scale", price: "$199", period: "/mo", desc: "High volume", features: ["Unlimited tokens", "Priority routing", "SLA guarantee", "Dedicated support"], cta: "Contact", href: "mailto:hello@bhairab.ai", hl: false },
];

export default function Home() {
  return (
    <div className="min-h-screen bg-[#0A0A0B] text-[#ECECEC] antialiased selection:bg-[#E5392B]/30">
      {/* Nav */}
      <header className="sticky top-0 z-50 bg-[#0A0A0B]/80 backdrop-blur border-b border-[#1E1E20]">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/"><Logo /></Link>
          <nav className="hidden md:flex items-center gap-8 text-sm text-[#8A8A8F]">
            <a href="#how" className="hover:text-[#ECECEC] transition-colors">How it works</a>
            <a href="#pricing" className="hover:text-[#ECECEC] transition-colors">Pricing</a>
            <Link href="/docs" className="hover:text-[#ECECEC] transition-colors">Docs</Link>
          </nav>
          <AuthNav />
        </div>
      </header>

      {/* Hero */}
      <section className="max-w-6xl mx-auto px-6 pt-24 pb-20 text-center">
        <div className="flex justify-center mb-10">
          <EyeMark size={64} />
        </div>
        <div className="inline-flex items-center gap-2 border border-[#1E1E20] rounded-full px-3.5 py-1.5 text-xs text-[#8A8A8F] mb-8">
          <span className="w-1.5 h-1.5 bg-[#E5392B] rounded-full" />
          Live on Bittensor SN64
        </div>
        <h1 className="text-5xl md:text-7xl font-semibold tracking-tight leading-[1.05] mb-6">
          The guardian of<br />
          <span className="text-[#8A8A8F]">decentralized AI.</span>
        </h1>
        <p className="text-lg text-[#8A8A8F] max-w-xl mx-auto mb-10 leading-relaxed">
          One API to Bittensor&apos;s decentralized inference network. 10× cheaper than OpenAI,
          fiat billing, and an SLA the network can&apos;t break on its own.
        </p>
        <HeroCTA />

        {/* Code block */}
        <div className="max-w-2xl mx-auto text-left rounded-xl border border-[#1E1E20] overflow-hidden">
          <div className="flex items-center justify-between bg-[#111113] border-b border-[#1E1E20] px-4 py-3">
            <div className="flex items-center gap-2 text-[#8A8A8F]">
              <EyeMark size={14} />
              <span className="text-xs tracking-widest uppercase">Drop-in for OpenAI</span>
            </div>
            <span className="text-xs text-[#8A8A8F] font-mono">python</span>
          </div>
          <pre className="bg-[#0C0C0D] p-5 text-sm font-mono text-[#B7B7BC] overflow-x-auto leading-relaxed">{`from openai import OpenAI

client = OpenAI(
    api_key=`}<span className="text-[#E5392B]">{`"sk_live_..."`}</span>{`,
    base_url=`}<span className="text-[#C9A227]">{`"${API_HOST}/v1"`}</span>{`  # only change
)

resp = client.chat.completions.create(
    model=`}<span className="text-[#C9A227]">{`"auto"`}</span>{`,
    messages=[{`}<span className="text-[#8A8A8F]">{`"role"`}</span>{`: `}<span className="text-[#C9A227]">{`"user"`}</span>{`, `}<span className="text-[#8A8A8F]">{`"content"`}</span>{`: `}<span className="text-[#C9A227]">{`"Hello"`}</span>{`}]
)`}</pre>
        </div>
      </section>

      {/* Price comparison */}
      <section className="max-w-6xl mx-auto px-6 py-16 border-t border-[#1E1E20]">
        <p className="text-xs font-medium text-[#8A8A8F] uppercase tracking-[0.2em] text-center mb-8">Price per 1M tokens</p>
        <div className="max-w-2xl mx-auto border border-[#1E1E20] rounded-xl divide-y divide-[#1E1E20] overflow-hidden">
          {COMPARISON.map((r) => (
            <div key={r.label} className={`flex items-center justify-between px-6 py-4 ${r.us ? "bg-[#111113]" : ""}`}>
              <div className="flex items-center gap-2.5">
                {r.us && <EyeMark size={16} />}
                <span className={r.us ? "text-sm font-medium text-[#ECECEC]" : "text-sm text-[#8A8A8F]"}>{r.label}</span>
                <span className="text-xs text-[#55555B]">{r.provider}</span>
              </div>
              <div className="flex gap-6 text-sm">
                <span className="text-[#55555B]">in <span className={r.us ? "text-[#E5392B] font-semibold" : "text-[#ECECEC]"}>{r.input}</span></span>
                <span className="text-[#55555B]">out <span className={r.us ? "text-[#E5392B] font-semibold" : "text-[#ECECEC]"}>{r.output}</span></span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Pillars */}
      <section className="max-w-6xl mx-auto px-6 py-20 border-t border-[#1E1E20]">
        <div className="grid md:grid-cols-3 gap-px bg-[#1E1E20] border border-[#1E1E20] rounded-xl overflow-hidden">
          {PILLARS.map((p) => (
            <div key={p.k} className="bg-[#0A0A0B] p-8">
              <div className="text-xs font-mono text-[#E5392B] mb-6">{p.k}</div>
              <h3 className="text-lg font-semibold mb-3">{p.title}</h3>
              <p className="text-sm text-[#8A8A8F] leading-relaxed">{p.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="max-w-6xl mx-auto px-6 py-20 border-t border-[#1E1E20]">
        <h2 className="text-3xl font-semibold tracking-tight text-center mb-2">How it works</h2>
        <p className="text-[#8A8A8F] text-sm text-center mb-14">Three steps to decentralized inference</p>
        <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
          {STEPS.map((s) => (
            <div key={s.n} className="text-center">
              <div className="w-9 h-9 mx-auto mb-5 border border-[#1E1E20] rounded-lg flex items-center justify-center text-sm font-mono text-[#E5392B]">{s.n}</div>
              <h3 className="font-semibold mb-2">{s.t}</h3>
              <p className="text-sm text-[#8A8A8F] leading-relaxed">{s.d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Guardian / Bittensor */}
      <section className="border-y border-[#1E1E20] py-20">
        <div className="max-w-3xl mx-auto px-6 text-center">
          <EyeMark size={40} className="mx-auto mb-8" />
          <h2 className="text-2xl font-semibold tracking-tight mb-5">Named for the guardian</h2>
          <p className="text-[#8A8A8F] text-sm leading-relaxed mb-4">
            Bhairab is the fierce protector deity of Kathmandu — the watchful guardian who never sleeps.
            Bittensor is a $3.3B decentralized AI network of GPU miners, 10× cheaper than the cloud — but
            chaotic, unreliable, and walled behind crypto.
          </p>
          <p className="text-[#8A8A8F] text-sm leading-relaxed">
            Bhairab stands between you and that chaos. It routes to the right subnet, pays miners in TAO,
            fails over when the network stalls, and bills you in fiat. Always watching. Never down.
          </p>
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="max-w-6xl mx-auto px-6 py-24">
        <h2 className="text-3xl font-semibold tracking-tight text-center mb-2">Pricing</h2>
        <p className="text-[#8A8A8F] text-sm text-center mb-14">Always cheaper than the cloud.</p>
        <div className="grid md:grid-cols-3 gap-5 max-w-4xl mx-auto">
          {PRICING.map((p) => (
            <div key={p.name} className={`rounded-xl p-8 flex flex-col border ${p.hl ? "border-[#E5392B]/40 bg-[#111113]" : "border-[#1E1E20]"}`}>
              <div className="text-xs font-medium uppercase tracking-[0.2em] text-[#8A8A8F] mb-4">{p.name}</div>
              <div className="mb-1">
                <span className="text-4xl font-semibold">{p.price}</span>
                <span className="text-sm text-[#55555B]">{p.period}</span>
              </div>
              <div className="text-sm text-[#8A8A8F] mb-6">{p.desc}</div>
              <ul className="space-y-2.5 mb-8 flex-1">
                {p.features.map((f) => (
                  <li key={f} className="text-sm text-[#B7B7BC] flex items-center gap-2.5">
                    <span className="text-[#E5392B] text-xs">◆</span> {f}
                  </li>
                ))}
              </ul>
              <Link href={p.href} className={`text-center py-2.5 rounded-md text-sm font-semibold transition-colors ${p.hl ? "bg-[#E5392B] text-white hover:bg-[#cf3325]" : "border border-[#1E1E20] text-[#ECECEC] hover:border-[#33333A]"}`}>
                {p.cta}
              </Link>
            </div>
          ))}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-[#1E1E20] py-10">
        <div className="max-w-6xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-[#55555B]">
          <div className="flex items-center gap-2.5">
            <EyeMark size={18} />
            <span>Bhairab © 2026 — The guardian of decentralized AI</span>
          </div>
          <div className="flex gap-6">
            <Link href="/docs" className="hover:text-[#ECECEC] transition-colors">Docs</Link>
            <a href="mailto:hello@bhairab.ai" className="hover:text-[#ECECEC] transition-colors">Contact</a>
          </div>
        </div>
      </footer>
    </div>
  );
}

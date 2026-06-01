import Link from "next/link";

const PRICING = [
  {
    name: "Free",
    price: "$0",
    period: "",
    description: "Try it out",
    features: ["100k tokens / month", "SN64 Chutes access", "Community support"],
    cta: "Get started",
    href: "/signup",
    highlight: false,
  },
  {
    name: "Builder",
    price: "$29",
    period: "/mo",
    description: "For production apps",
    features: ["10M tokens / month", "All subnets", "Smart routing", "Email support", "Usage dashboard"],
    cta: "Start building",
    href: "/signup",
    highlight: true,
  },
  {
    name: "Scale",
    price: "$199",
    period: "/mo",
    description: "High-volume workloads",
    features: ["Unlimited tokens", "Priority routing", "SLA guarantee", "Dedicated support", "Custom models"],
    cta: "Contact us",
    href: "mailto:hello@taogateway.dev",
    highlight: false,
  },
];

const COMPARISON = [
  { label: "GPT-4o", provider: "OpenAI", input: "$5.00", output: "$15.00", highlight: false },
  { label: "Claude Sonnet", provider: "Anthropic", input: "$3.00", output: "$15.00", highlight: false },
  { label: "DeepSeek V3 via SN64", provider: "TAO Gateway", input: "$0.50", output: "$1.50", highlight: true },
];

const STEPS = [
  { num: "1", title: "Get an API key", desc: "Sign up with your email. No wallet, no crypto, no TAO required." },
  { num: "2", title: "Change one line", desc: "Point your existing OpenAI SDK at our endpoint. Zero other changes." },
  { num: "3", title: "We handle everything", desc: "We route to the best subnet, pay miners in TAO, and bill you in USD." },
];

export default function Home() {
  return (
    <div className="min-h-screen bg-white text-gray-900">

      {/* Nav */}
      <header className="sticky top-0 z-50 bg-white/90 backdrop-blur border-b border-gray-100">
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <span className="font-semibold text-gray-900 tracking-tight">TAO Gateway</span>
            <nav className="hidden md:flex items-center gap-6 text-sm text-gray-500">
              <a href="#how" className="hover:text-gray-900 transition-colors">How it works</a>
              <a href="#pricing" className="hover:text-gray-900 transition-colors">Pricing</a>
              <a href="https://github.com/Ayoshiss/tao-gateway" target="_blank" className="hover:text-gray-900 transition-colors">Docs</a>
            </nav>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/login" className="text-sm text-gray-600 hover:text-gray-900 transition-colors">Sign in</Link>
            <Link href="/signup" className="text-sm bg-gray-900 text-white px-4 py-2 rounded-lg font-medium hover:bg-gray-700 transition-colors">
              Get API key →
            </Link>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="max-w-6xl mx-auto px-6 pt-20 pb-16 text-center">
        <div className="inline-flex items-center gap-2 bg-gray-50 border border-gray-200 rounded-full px-4 py-1.5 text-xs text-gray-500 mb-8">
          <span className="w-1.5 h-1.5 bg-green-500 rounded-full" />
          Now live — SN64 Chutes inference
        </div>

        <h1 className="text-5xl md:text-6xl font-bold tracking-tight text-gray-900 mb-6 leading-[1.1]">
          Bittensor AI.<br />
          <span className="text-gray-400">One API. Fiat billing.</span>
        </h1>

        <p className="text-lg text-gray-500 max-w-xl mx-auto mb-10 leading-relaxed">
          Access Bittensor&apos;s decentralized AI subnets with a standard REST API and a credit card.
          No wallet. No TAO. No crypto setup.
        </p>

        <div className="flex items-center justify-center gap-3 mb-16">
          <Link href="/signup" className="bg-gray-900 text-white px-6 py-3 rounded-lg text-sm font-semibold hover:bg-gray-700 transition-colors">
            Get free API key
          </Link>
          <a href="#how" className="border border-gray-200 text-gray-600 px-6 py-3 rounded-lg text-sm font-medium hover:border-gray-400 transition-colors">
            See how it works
          </a>
        </div>

        {/* Code block */}
        <div className="max-w-2xl mx-auto text-left rounded-xl border border-gray-200 overflow-hidden shadow-sm">
          <div className="flex items-center justify-between bg-gray-50 border-b border-gray-200 px-4 py-3">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-red-400" />
              <span className="w-3 h-3 rounded-full bg-yellow-400" />
              <span className="w-3 h-3 rounded-full bg-green-400" />
            </div>
            <span className="text-xs text-gray-400 font-mono">Python</span>
          </div>
          <pre className="bg-white p-5 text-sm font-mono text-gray-700 overflow-x-auto leading-relaxed">{`from openai import OpenAI

client = OpenAI(
    api_key=`}<span className="text-green-600">{`"sk_live_..."`}</span>{`,
    base_url=`}<span className="text-blue-600">{`"https://api.taogateway.dev/v1"`}</span>{`  # ← only change
)

response = client.chat.completions.create(
    model=`}<span className="text-orange-500">{`"gpt-4o"`}</span>{`,
    messages=[{`}<span className="text-purple-600">{`"role"`}</span>{`: `}<span className="text-green-600">{`"user"`}</span>{`, `}<span className="text-purple-600">{`"content"`}</span>{`: `}<span className="text-green-600">{`"Hello!"`}</span>{`}]
)
`}<span className="text-gray-400">{`# Routes to Bittensor SN64 · 90% cheaper than OpenAI`}</span></pre>
        </div>
      </section>

      {/* Price comparison */}
      <section className="max-w-6xl mx-auto px-6 py-16 border-t border-gray-100">
        <p className="text-xs font-medium text-gray-400 uppercase tracking-widest text-center mb-8">Price per 1M tokens</p>
        <div className="max-w-2xl mx-auto divide-y divide-gray-100 border border-gray-200 rounded-xl overflow-hidden">
          {COMPARISON.map((row) => (
            <div key={row.label} className={`flex items-center justify-between px-6 py-4 ${row.highlight ? "bg-gray-50" : "bg-white"}`}>
              <div>
                <span className="text-sm font-medium text-gray-900">{row.label}</span>
                <span className="ml-2 text-xs text-gray-400">{row.provider}</span>
              </div>
              <div className="flex gap-6 text-sm">
                <span className="text-gray-500">In: <span className={row.highlight ? "font-semibold text-green-600" : "text-gray-900"}>{row.input}</span></span>
                <span className="text-gray-500">Out: <span className={row.highlight ? "font-semibold text-green-600" : "text-gray-900"}>{row.output}</span></span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="max-w-6xl mx-auto px-6 py-16 border-t border-gray-100">
        <h2 className="text-2xl font-bold text-center mb-2">How it works</h2>
        <p className="text-gray-500 text-sm text-center mb-12">Three steps from zero to decentralized AI</p>
        <div className="grid md:grid-cols-3 gap-8">
          {STEPS.map((step) => (
            <div key={step.num} className="relative p-6 rounded-xl border border-gray-100 bg-gray-50">
              <div className="w-8 h-8 bg-gray-900 text-white rounded-lg flex items-center justify-center text-xs font-bold mb-4">{step.num}</div>
              <h3 className="font-semibold text-gray-900 mb-2">{step.title}</h3>
              <p className="text-sm text-gray-500 leading-relaxed">{step.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* What is Bittensor */}
      <section className="bg-gray-50 border-y border-gray-100 py-16">
        <div className="max-w-3xl mx-auto px-6 text-center">
          <h2 className="text-2xl font-bold mb-4">Built on Bittensor</h2>
          <p className="text-gray-500 text-sm leading-relaxed mb-4">
            Bittensor is a decentralized AI network with 256 specialized subnets — each a marketplace of GPU miners competing to deliver the best output.
            Subnet 64 (Chutes) provides LLM inference at 90% below AWS. Subnet 62 (Ridges) beats Claude on coding benchmarks.
          </p>
          <p className="text-gray-500 text-sm leading-relaxed">
            TAO Gateway routes your requests to the right subnet, pays miners in TAO on your behalf, and bills you in USD.
            You get decentralized AI without ever touching crypto.
          </p>
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="max-w-6xl mx-auto px-6 py-20">
        <h2 className="text-2xl font-bold text-center mb-2">Simple pricing</h2>
        <p className="text-gray-500 text-sm text-center mb-12">Cost-plus 30% above subnet wholesale. Always cheaper than OpenAI.</p>
        <div className="grid md:grid-cols-3 gap-6">
          {PRICING.map((plan) => (
            <div key={plan.name} className={`rounded-xl p-8 flex flex-col border ${plan.highlight ? "border-gray-900 bg-gray-900 text-white" : "border-gray-200 bg-white"}`}>
              <div className={`text-xs font-medium uppercase tracking-widest mb-4 ${plan.highlight ? "text-gray-400" : "text-gray-400"}`}>{plan.name}</div>
              <div className="mb-1">
                <span className="text-4xl font-bold">{plan.price}</span>
                <span className={`text-sm ${plan.highlight ? "text-gray-400" : "text-gray-400"}`}>{plan.period}</span>
              </div>
              <div className={`text-sm mb-6 ${plan.highlight ? "text-gray-400" : "text-gray-500"}`}>{plan.description}</div>
              <ul className="space-y-2.5 mb-8 flex-1">
                {plan.features.map((f) => (
                  <li key={f} className={`text-sm flex items-center gap-2 ${plan.highlight ? "text-gray-300" : "text-gray-600"}`}>
                    <svg className={`w-4 h-4 shrink-0 ${plan.highlight ? "text-gray-400" : "text-gray-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    {f}
                  </li>
                ))}
              </ul>
              <Link href={plan.href} className={`text-center py-2.5 rounded-lg text-sm font-semibold transition-colors ${plan.highlight ? "bg-white text-gray-900 hover:bg-gray-100" : "bg-gray-900 text-white hover:bg-gray-700"}`}>
                {plan.cta}
              </Link>
            </div>
          ))}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-100 py-10">
        <div className="max-w-6xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-gray-400">
          <span>TAO Gateway © 2026</span>
          <div className="flex gap-6">
            <a href="https://github.com/Ayoshiss/tao-gateway" target="_blank" className="hover:text-gray-900 transition-colors">GitHub</a>
            <a href="mailto:hello@taogateway.dev" className="hover:text-gray-900 transition-colors">Contact</a>
            <a href="#" className="hover:text-gray-900 transition-colors">Terms</a>
          </div>
        </div>
      </footer>
    </div>
  );
}

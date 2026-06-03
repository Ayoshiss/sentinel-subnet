import Link from "next/link";
import { EyeMark, Logo } from "@/components/brand";

const GW = "https://tao-gateway.fly.dev"; // swaps to api.bhairab.ai in Phase 2

const NAV = [
  { id: "quickstart", label: "Quickstart" },
  { id: "auth", label: "Authentication" },
  { id: "chat", label: "Chat completions" },
  { id: "streaming", label: "Streaming" },
  { id: "models", label: "Models & routing" },
  { id: "headers", label: "Response headers" },
  { id: "errors", label: "Errors" },
  { id: "limits", label: "Rate limits & billing" },
];

function Code({ children, lang }: { children: string; lang?: string }) {
  return (
    <div className="border border-[#1E1E20] rounded-lg overflow-hidden my-4">
      {lang && (
        <div className="bg-[#111113] border-b border-[#1E1E20] px-4 py-2 flex items-center gap-2">
          <EyeMark size={13} />
          <span className="text-xs text-[#8A8A8F] font-mono ml-0.5">{lang}</span>
        </div>
      )}
      <pre className="p-4 text-xs font-mono text-[#B7B7BC] overflow-x-auto leading-relaxed bg-[#0C0C0D] whitespace-pre">{children}</pre>
    </div>
  );
}

function Tag({ children }: { children: string }) {
  return <code className="text-sm bg-[#111113] border border-[#1E1E20] px-1.5 py-0.5 rounded text-[#ECECEC]">{children}</code>;
}

function H2({ id, children }: { id: string; children: string }) {
  return (
    <h2 id={id} className="text-2xl font-semibold tracking-tight text-[#ECECEC] mt-16 mb-4 scroll-mt-24 pt-2 border-t border-[#1E1E20] first:border-0 first:mt-0 first:pt-0">
      {children}
    </h2>
  );
}

export default function Docs() {
  return (
    <div className="min-h-screen bg-[#0A0A0B] text-[#ECECEC] antialiased selection:bg-[#E5392B]/30">
      <header className="sticky top-0 z-50 bg-[#0A0A0B]/80 backdrop-blur border-b border-[#1E1E20]">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/"><Logo /></Link>
            <span className="text-sm text-[#55555B]">/ Docs</span>
          </div>
          <Link href="/signup" className="text-sm bg-[#E5392B] text-white px-4 py-2 rounded-md font-medium hover:bg-[#cf3325] transition-colors">
            Get API key
          </Link>
        </div>
      </header>

      <div className="max-w-6xl mx-auto px-6 flex gap-12">
        <aside className="hidden lg:block w-48 shrink-0 py-12">
          <nav className="sticky top-24 space-y-1">
            {NAV.map((n) => (
              <a key={n.id} href={`#${n.id}`} className="block text-sm text-[#8A8A8F] hover:text-[#ECECEC] py-1.5 transition-colors">
                {n.label}
              </a>
            ))}
            <a href={`${GW}/health`} target="_blank" className="block text-sm text-[#55555B] hover:text-[#ECECEC] py-1.5 mt-4 border-t border-[#1E1E20] pt-4 transition-colors">
              API status ↗
            </a>
          </nav>
        </aside>

        <main className="flex-1 min-w-0 py-12 max-w-2xl">
          <h1 className="text-3xl font-semibold tracking-tight mb-3">API Reference</h1>
          <p className="text-[#8A8A8F] leading-relaxed">
            Bhairab is an OpenAI-compatible API for Bittensor&apos;s decentralized AI network.
            If you&apos;ve used the OpenAI API, you already know how to use this — change one line
            (the base URL) and your existing code works.
          </p>

          <div className="mt-6 inline-flex items-center gap-2 text-sm bg-[#111113] border border-[#1E1E20] rounded-lg px-4 py-2 font-mono">
            <span className="text-[#55555B]">Base URL</span>
            <span className="text-[#ECECEC]">{GW}/v1</span>
          </div>

          <H2 id="quickstart">Quickstart</H2>
          <p className="text-[#8A8A8F] leading-relaxed">
            <Link href="/signup" className="text-[#ECECEC] underline decoration-[#33333A]">Get a free API key</Link> (100k tokens included, no card required),
            then make your first call. Use <Tag>model: &quot;auto&quot;</Tag> to let the router pick the
            most cost-efficient model per prompt.
          </p>
          <Code lang="python">{`from openai import OpenAI

client = OpenAI(
    api_key="sk_live_...",
    base_url="${GW}/v1",   # only change from OpenAI
)

resp = client.chat.completions.create(
    model="auto",
    messages=[{"role": "user", "content": "Hello!"}],
)
print(resp.choices[0].message.content)`}</Code>

          <H2 id="auth">Authentication</H2>
          <p className="text-[#8A8A8F] leading-relaxed">
            Pass your API key as a Bearer token. Keys start with <Tag>sk_live_</Tag>.
            Manage and revoke keys from your <Link href="/dashboard" className="text-[#ECECEC] underline decoration-[#33333A]">dashboard</Link>.
          </p>
          <Code>{`Authorization: Bearer sk_live_your_key_here`}</Code>

          <H2 id="chat">Chat completions</H2>
          <p className="text-[#8A8A8F] leading-relaxed">
            <Tag>POST /v1/chat/completions</Tag> — accepts and returns the standard OpenAI
            chat-completions shape.
          </p>
          <Code lang="cURL">{`curl ${GW}/v1/chat/completions \\
  -H "Authorization: Bearer sk_live_..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "auto",
    "messages": [
      {"role": "system", "content": "You are concise."},
      {"role": "user", "content": "What is Bittensor?"}
    ]
  }'`}</Code>
          <p className="text-[#8A8A8F] leading-relaxed text-sm">Response (OpenAI-compatible):</p>
          <Code lang="json">{`{
  "id": "chatcmpl-...",
  "object": "chat.completion",
  "model": "deepseek-ai/DeepSeek-V3.2-TEE",  // the model that served it
  "choices": [{
    "index": 0,
    "message": { "role": "assistant", "content": "Bittensor is..." },
    "finish_reason": "stop"
  }],
  "usage": { "prompt_tokens": 18, "completion_tokens": 92, "total_tokens": 110 }
}`}</Code>

          <H2 id="streaming">Streaming</H2>
          <p className="text-[#8A8A8F] leading-relaxed">
            Set <Tag>stream: true</Tag> to receive tokens as Server-Sent Events, exactly like OpenAI.
            The stream ends with <Tag>data: [DONE]</Tag>.
          </p>
          <Code lang="python">{`stream = client.chat.completions.create(
    model="auto",
    messages=[{"role": "user", "content": "Write a haiku"}],
    stream=True,
)
for chunk in stream:
    print(chunk.choices[0].delta.content or "", end="", flush=True)`}</Code>

          <H2 id="models">Models & routing</H2>
          <p className="text-[#8A8A8F] leading-relaxed">
            Pass <Tag>model: &quot;auto&quot;</Tag> and the router classifies each prompt and sends it to
            the cheapest capable model. Or pin a specific model. OpenAI model names are accepted
            and mapped to equivalents.
          </p>
          <div className="overflow-x-auto my-4">
            <table className="w-full text-sm border border-[#1E1E20] rounded-lg overflow-hidden">
              <thead className="bg-[#111113] text-[#8A8A8F]">
                <tr>
                  <th className="text-left font-medium px-4 py-2.5 border-b border-[#1E1E20]">model value</th>
                  <th className="text-left font-medium px-4 py-2.5 border-b border-[#1E1E20]">Routes to</th>
                  <th className="text-left font-medium px-4 py-2.5 border-b border-[#1E1E20]">Best for</th>
                </tr>
              </thead>
              <tbody className="text-[#B7B7BC]">
                {[
                  ["auto", "router picks per prompt", "Recommended default"],
                  ["gpt-4o / gpt-4", "DeepSeek V3.2", "Complex reasoning, code"],
                  ["gpt-4o-mini", "Gemma 4 31B Turbo", "General chat, fast"],
                  ["gpt-3.5-turbo", "Mistral Nemo", "Simple, cheapest"],
                  ["deepseek / gemma / mistral", "that model directly", "Pin a specific model"],
                  ["qwen-coder", "Qwen2.5 Coder 32B", "Code generation"],
                ].map((r) => (
                  <tr key={r[0]} className="border-b border-[#1E1E20] last:border-0">
                    <td className="px-4 py-2.5 font-mono text-xs text-[#ECECEC]">{r[0]}</td>
                    <td className="px-4 py-2.5">{r[1]}</td>
                    <td className="px-4 py-2.5 text-[#8A8A8F]">{r[2]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-[#8A8A8F] leading-relaxed text-sm">
            Inference runs on Bittensor SN64 (Chutes). If the decentralized network is at capacity,
            requests transparently fail over to a centralized backstop so your app never sees an
            outage — the <Tag>X-Routed-Subnet</Tag> header tells you exactly where each request ran.
          </p>

          <H2 id="headers">Response headers</H2>
          <div className="overflow-x-auto my-4">
            <table className="w-full text-sm border border-[#1E1E20] rounded-lg overflow-hidden">
              <tbody className="text-[#B7B7BC]">
                {[
                  ["X-Routed-Subnet", "Which model/provider served the request, e.g. SN64-Chutes/...-TEE or groq-backstop"],
                  ["X-RateLimit-Remaining", "Requests left in the current minute window"],
                  ["X-Latency-Ms", "Gateway-measured latency for the request"],
                ].map((r) => (
                  <tr key={r[0]} className="border-b border-[#1E1E20] last:border-0">
                    <td className="px-4 py-2.5 font-mono text-xs whitespace-nowrap align-top text-[#ECECEC]">{r[0]}</td>
                    <td className="px-4 py-2.5 text-[#8A8A8F]">{r[1]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <H2 id="errors">Errors</H2>
          <p className="text-[#8A8A8F] leading-relaxed">Standard HTTP status codes. Error bodies are JSON with an <Tag>error</Tag> field.</p>
          <div className="overflow-x-auto my-4">
            <table className="w-full text-sm border border-[#1E1E20] rounded-lg overflow-hidden">
              <thead className="bg-[#111113] text-[#8A8A8F]">
                <tr>
                  <th className="text-left font-medium px-4 py-2.5 border-b border-[#1E1E20]">Code</th>
                  <th className="text-left font-medium px-4 py-2.5 border-b border-[#1E1E20]">Meaning</th>
                </tr>
              </thead>
              <tbody className="text-[#B7B7BC]">
                {[
                  ["401", "Invalid or missing API key"],
                  ["402", "Insufficient balance — top up in the dashboard"],
                  ["429", "Rate limit exceeded — see Retry-After header"],
                  ["502", "All providers at capacity — retry in a moment"],
                ].map((r) => (
                  <tr key={r[0]} className="border-b border-[#1E1E20] last:border-0">
                    <td className="px-4 py-2.5 font-mono text-xs text-[#E5392B]">{r[0]}</td>
                    <td className="px-4 py-2.5 text-[#8A8A8F]">{r[1]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <H2 id="limits">Rate limits & billing</H2>
          <ul className="text-[#8A8A8F] leading-relaxed space-y-2 list-none pl-0">
            {[
              ["Free tier", "100k tokens to start, no card required."],
              ["Rate limit", "60 requests/minute by default. X-RateLimit-Remaining tracks your window."],
              ["Pricing", "$0.50 / 1M input tokens, $1.50 / 1M output tokens — billed against your prepaid balance. ~10× cheaper than OpenAI GPT-4o."],
              ["Top up", "credit packs via Stripe from your dashboard."],
            ].map(([k, v]) => (
              <li key={k} className="flex gap-2.5"><span className="text-[#E5392B] text-xs mt-1.5">◆</span><span><span className="text-[#ECECEC] font-medium">{k}:</span> {v}</span></li>
            ))}
          </ul>

          <div className="mt-16 border-t border-[#1E1E20] pt-8 flex items-center justify-between">
            <span className="text-sm text-[#55555B]">Questions? hello@bhairab.ai</span>
            <Link href="/signup" className="text-sm bg-[#E5392B] text-white px-5 py-2.5 rounded-md font-semibold hover:bg-[#cf3325] transition-colors">
              Get your API key →
            </Link>
          </div>
        </main>
      </div>
    </div>
  );
}

// Pre-transaction risk scan — the guardian leg of the agent stack.
// An agent built on Lattice's stack (tweetnacl/bs58) pays Bhairab per scan via
// the x402 "402 dance", then receives an AI verdict over LIVE signals BEFORE it
// would execute on-chain. THINK(scan) + PAY, no API key.
//
// Run:  NODE_PATH=~/Downloads/lattice/node_modules node demo/risk-scan-agent.js
//   optional: TOKEN=<solana mint> ACTION=buy AMOUNT=250
const nacl = require("tweetnacl");
const bs58lib = require("bs58");
const bs58 = bs58lib.default || bs58lib;
const { Buffer } = require("buffer");

const GATEWAY = process.env.GATEWAY || "http://localhost:8080";
const NETWORK = "solana";
const RESOURCE = "/v1/risk/scan";

// EXACT mirror of Lattice's buildSignedMessage()
const buildSignedMessage = ({ amount, asset, network, resource, nonce }) =>
  Buffer.from(JSON.stringify({ amount, asset, network, resource, nonce }));

async function main() {
  const kp = nacl.sign.keyPair();
  const pubkey = bs58.encode(Buffer.from(kp.publicKey));

  // The transaction the agent is ABOUT to make — scanned before it acts.
  const intent = {
    chain: "solana",
    token: process.env.TOKEN || "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", // BONK
    action: process.env.ACTION || "buy",
    amountUsd: Number(process.env.AMOUNT || 250),
  };
  const body = JSON.stringify(intent);
  const headers = { "Content-Type": "application/json" };

  console.log(`→ POST ${RESOURCE}  (no API key, no payment)`);
  console.log(`  intent: ${intent.action} $${intent.amountUsd} of ${intent.token.slice(0, 8)}… on ${intent.chain}`);
  let r = await fetch(`${GATEWAY}${RESOURCE}`, { method: "POST", headers, body });
  console.log(`← ${r.status} ${r.statusText}`);
  if (r.status !== 402) return console.log("expected 402:", await r.text());

  const env = JSON.parse(Buffer.from(r.headers.get("x-payment-required"), "base64").toString("utf8"));
  console.log(`  402 → pay ${env.maxAmountRequired} µUSDC, resource=${env.resource}  nonce=${env.nonce.slice(0, 10)}…`);

  // sign the payment authorization (ed25519, identical scheme to Lattice)
  const amount = env.maxAmountRequired;
  const msg = buildSignedMessage({ amount, asset: env.asset, network: NETWORK, resource: env.resource, nonce: env.nonce });
  const sig = nacl.sign.detached(msg, kp.secretKey);
  const proof = { from: pubkey, pubkey, signature: bs58.encode(Buffer.from(sig)), amount, asset: env.asset, network: NETWORK, nonce: env.nonce };
  const xpayment = Buffer.from(JSON.stringify(proof)).toString("base64");

  console.log(`→ signed payment as ${pubkey.slice(0, 8)}…  retrying with X-PAYMENT`);
  r = await fetch(`${GATEWAY}${RESOURCE}`, { method: "POST", headers: { ...headers, "X-PAYMENT": xpayment }, body });
  console.log(`← ${r.status} ${r.statusText}`);
  const v = await r.json();
  if (!v.verdict) return console.log("response:", JSON.stringify(v, null, 2));

  const mark = { proceed: "✅", caution: "⚠️ ", stop: "⛔" }[v.verdict] || "•";
  console.log(`\n${mark} VERDICT: ${v.verdict.toUpperCase()}  (confidence ${v.confidence}, via ${v.verdictSource})`);
  console.log(`   ${v.summary}`);
  (v.reasons || []).forEach((x) => console.log(`   • ${x}`));
  if (v.signals) {
    const s = v.signals;
    console.log(`   signals: liq $${Math.round(s.liquidityUsd).toLocaleString()}  24h ${s.priceChange24hPct}%  vol $${Math.round(s.volume24hUsd).toLocaleString()}  age ${s.ageDays.toFixed(0)}d  [${s.source}]`);
  }
  console.log(`\n   → THEN the agent would proceed to ACT on Lattice (MEV-proof) only if not "stop".`);
}
main().catch((e) => console.error(e));

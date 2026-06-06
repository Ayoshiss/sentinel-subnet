// x402 demo agent — proves the Bhairab × Lattice bridge.
// An agent built on Lattice's stack (tweetnacl/bs58) pays Bhairab per inference
// via the x402 "402 dance", with no API key. THINK + PAY end to end.
//
// Run:  NODE_PATH=~/Downloads/lattice/node_modules node demo/x402-agent.js
const nacl = require("tweetnacl");
const bs58lib = require("bs58");
const bs58 = bs58lib.default || bs58lib;
const { Buffer } = require("buffer");

const GATEWAY = process.env.GATEWAY || "http://localhost:8080";
const NETWORK = "solana";

// EXACT mirror of Lattice's buildSignedMessage()
const buildSignedMessage = ({ amount, asset, network, resource, nonce }) =>
  Buffer.from(JSON.stringify({ amount, asset, network, resource, nonce }));

async function main() {
  const kp = nacl.sign.keyPair();
  const pubkey = bs58.encode(Buffer.from(kp.publicKey));
  const body = JSON.stringify({
    model: "auto",
    messages: [{ role: "user", content: "In one sentence, what is a sealed-bid batch auction?" }],
  });
  const headers = { "Content-Type": "application/json" };

  console.log("→ POST /v1/chat/completions  (no API key, no payment)");
  let r = await fetch(`${GATEWAY}/v1/chat/completions`, { method: "POST", headers, body });
  console.log(`← ${r.status} ${r.statusText}`);
  if (r.status !== 402) return console.log("expected 402:", await r.text());

  const env = JSON.parse(Buffer.from(r.headers.get("x-payment-required"), "base64").toString("utf8"));
  console.log(`  402 envelope → pay ${env.maxAmountRequired} µUSDC to ${env.recipient.slice(0, 8)}…  nonce=${env.nonce.slice(0, 10)}…`);

  // sign the payment authorization (ed25519, identical scheme to Lattice)
  const amount = env.maxAmountRequired;
  const msg = buildSignedMessage({ amount, asset: env.asset, network: NETWORK, resource: env.resource, nonce: env.nonce });
  const sig = nacl.sign.detached(msg, kp.secretKey);
  const proof = { from: pubkey, pubkey, signature: bs58.encode(Buffer.from(sig)), amount, asset: env.asset, network: NETWORK, nonce: env.nonce };
  const xpayment = Buffer.from(JSON.stringify(proof)).toString("base64");

  console.log(`→ signed payment as ${pubkey.slice(0, 8)}…  retrying with X-PAYMENT`);
  r = await fetch(`${GATEWAY}/v1/chat/completions`, { method: "POST", headers: { ...headers, "X-PAYMENT": xpayment }, body });
  console.log(`← ${r.status} ${r.statusText}`);
  const data = await r.json();
  if (data.choices) {
    console.log(`\n✅ PAID INFERENCE (think + pay, no account):\n   "${data.choices[0].message.content.trim()}"`);
    console.log(`   model=${data.model}  tokens=${data.usage?.total_tokens}  routed=${r.headers.get("x-routed-subnet") || "?"}`);
  } else {
    console.log("response:", JSON.stringify(data));
  }
}
main().catch((e) => console.error(e));

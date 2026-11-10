// Runs web/verify/sentinel-verify.js for tests/test_verify_page.py.
// Reads {cases: [...], canonical: [...]} on stdin and prints the results.
// Intel's signature is stubbed: that part is dcap-qvl's, tested upstream and
// in the browser. Everything Sentinel adds on top is exercised here.
import { readFileSync } from "fs";
const V = await import(new URL("../web/verify/sentinel-verify.js", import.meta.url));
const input = JSON.parse(readFileSync(0, "utf8"));
const intel = async () => ({ status: "UpToDate", advisory_ids: [] });
const out = { cases: [], canonical: [] };
for (const c of input.cases) {
  const r = await V.verifyProof(c.proof, { registry: c.registry, intel, broker: c.broker || "", nonce: c.nonce || "" });
  out.cases.push({ ok: r.ok, checks: Object.fromEntries(r.checks.map((x) => [x.id, [x.ok, x.detail]])) });
}
for (const text of input.canonical) out.canonical.push(V.canonical(V.parseExact(text)));
process.stdout.write(JSON.stringify(out));

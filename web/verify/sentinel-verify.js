// Check a Sentinel answer in the browser, without trusting Sentinel.
//
// A port of the subnet validator's checks (sentinel/tdx/verifier.py,
// sentinel/tdx/eventlog.py, sentinel/attestation.py). Intel's part, the quote
// signature and TCB status, is Phala's dcap-qvl, the same library the
// validator uses, passed in as `intel` so this file has no dependencies and
// runs unchanged in Node for the cross-tests (tests/test_verify_page.py).
//
// Every check returns {id, ok, title, detail}. `ok` is true, false, or null
// for "not shown" (a claim this proof cannot make, stated rather than failed).

const BODY = 48;
const REG = { MRTD: 136, RTMR0: 328, RTMR1: 376, RTMR2: 424, RTMR3: 472 };
const REPORT_DATA = 520;
const TD_ATTRIBUTES = 120;
const TD_DEBUG = 1n;
const MAX_EVENT_LOG = 1 << 20;
const ALLOWED_TCB = new Set(["UpToDate"]);

const EV_NO_ACTION = 0x3;
const EV_SEPARATOR = 0x4;
const EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001;
const EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003;
const EV_EFI_GPT_EVENT = 0x80000006;
const EV_EFI_ACTION = 0x80000007;
const EV_EFI_VARIABLE_AUTHORITY = 0x800000e0;
const DIGEST_SIZES = { 0x4: 20, 0xb: 32, 0xc: 48, 0xd: 64 };

// -- bytes and hashes ---------------------------------------------------------

export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export function unhex(s) {
  if (typeof s !== "string" || s.length % 2 || /[^0-9a-f]/i.test(s)) throw new Error("not hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
const utf8 = (s) => new TextEncoder().encode(s);
const concat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
async function digest(alg, bytes) { return new Uint8Array(await crypto.subtle.digest(alg, bytes)); }
const sha384 = (b) => digest("SHA-384", b);
const sha512 = (b) => digest("SHA-512", b);
const sha384hex = async (s) => hex(await sha384(utf8(s)));
function contains(hay, needle) {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}
function b64(s) {
  const bin = atob(s.replace(/\s+/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// -- Python-compatible canonical JSON -----------------------------------------
// The miner hashes json.dumps(result, sort_keys=True, separators=(",", ":")).
// To recompute that hash the answer must be parsed without losing how numbers
// were written (1.0 is not 1 to Python), and re-encoded with Python's escaping.

class Num { constructor(raw) { this.raw = raw; } }

export function parseExact(text) {
  let i = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const fail = (m) => { throw new Error(`not valid JSON at ${i}: ${m}`); };
  function value() {
    ws();
    const c = text[i];
    if (c === "{") {
      i++; const o = {}; ws();
      if (text[i] === "}") { i++; return o; }
      for (;;) {
        ws(); if (text[i] !== '"') fail("expected key");
        const k = str(); ws(); if (text[i++] !== ":") fail("expected :");
        o[k] = value(); ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; return o; }
        fail("expected , or }");
      }
    }
    if (c === "[") {
      i++; const a = []; ws();
      if (text[i] === "]") { i++; return a; }
      for (;;) {
        a.push(value()); ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; return a; }
        fail("expected , or ]");
      }
    }
    if (c === '"') return str();
    for (const [w, v] of [["true", true], ["false", false], ["null", null], ["NaN", new Num("NaN")],
                          ["Infinity", new Num("Infinity")], ["-Infinity", new Num("-Infinity")]]) {
      if (text.startsWith(w, i)) { i += w.length; return v; }
    }
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i));
    if (!m) fail("unexpected character");
    i += m[0].length;
    return new Num(m[0]);
  }
  function str() {
    const start = i; i++;
    while (i < text.length && text[i] !== '"') { if (text[i] === "\\") i++; i++; }
    if (i >= text.length) fail("unterminated string");
    i++;
    return JSON.parse(text.slice(start, i));
  }
  const v = value(); ws();
  if (i !== text.length) fail("trailing data");
  return v;
}

function pyString(s) {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (cp < 0x20 || (cp > 0x7e && cp <= 0xffff)) out += "\\u" + cp.toString(16).padStart(4, "0");
    else if (cp > 0xffff) {
      const v = cp - 0x10000;
      out += "\\u" + (0xd800 + (v >> 10)).toString(16) + "\\u" + (0xdc00 + (v & 0x3ff)).toString(16);
    } else out += ch;
  }
  return out + '"';
}

// Python sorts keys by code point; JS sort on strings compares UTF-16 units.
// They differ only for characters above U+FFFF, so compare code points.
function pyKeyOrder(a, b) {
  const x = Array.from(a, (c) => c.codePointAt(0)), y = Array.from(b, (c) => c.codePointAt(0));
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

export function canonical(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (v instanceof Num) return v.raw;
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error("parse with parseExact so numbers keep their form");
    return String(v);
  }
  if (typeof v === "string") return pyString(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).sort(pyKeyOrder).map((k) => pyString(k) + ":" + canonical(v[k])).join(",") + "}";
}

const plain = (v) => (v instanceof Num ? Number(v.raw) : v);

// -- the quote and the event log ----------------------------------------------

export function registers(quote) {
  const out = {};
  for (const [k, o] of Object.entries(REG)) out[k] = hex(quote.subarray(BODY + o, BODY + o + 48));
  return out;
}

export async function inflate(data) {
  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate"));
  const reader = stream.getReader();
  const parts = []; let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX_EVENT_LOG) { reader.cancel(); throw new Error("event log larger than any firmware table"); }
    parts.push(value);
  }
  const out = new Uint8Array(size); let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

export function events(log) {
  const dv = new DataView(log.buffer, log.byteOffset, log.byteLength);
  let off = 32 + dv.getUint32(28, true);
  const out = [];
  while (off + 12 <= log.length) {
    const mr = dv.getUint32(off, true), type = dv.getUint32(off + 4, true), count = dv.getUint32(off + 8, true);
    if (mr === 0xffffffff || (mr === 0 && type === 0) || count > 8) break;
    let p = off + 12, dg = new Uint8Array(0);
    for (let n = 0; n < count; n++) {
      const alg = dv.getUint16(p, true), size = DIGEST_SIZES[alg];
      if (size === undefined) throw new Error(`unknown digest algorithm ${alg}`);
      if (alg === 0xc) dg = log.slice(p + 2, p + 2 + size);
      p += 2 + size;
    }
    const size = dv.getUint32(p, true);
    if (p + 4 + size > log.length) throw new Error("event runs past the end of the log");
    out.push({ mr, type, digest: dg, data: log.slice(p + 4, p + 4 + size) });
    off = p + 4 + size;
  }
  return out;
}

export async function replay(evs) {
  const mrs = { 1: new Uint8Array(48), 2: new Uint8Array(48), 3: new Uint8Array(48), 4: new Uint8Array(48) };
  for (const e of evs) if (e.type !== EV_NO_ACTION && mrs[e.mr]) mrs[e.mr] = await sha384(concat(mrs[e.mr], e.digest));
  return { RTMR0: hex(mrs[1]), RTMR1: hex(mrs[2]), RTMR2: hex(mrs[3]), RTMR3: hex(mrs[4]) };
}

function variable(e) {
  const dv = new DataView(e.data.buffer, e.data.byteOffset, e.data.byteLength);
  const len = Number(dv.getBigUint64(16, true));
  const name = new TextDecoder("utf-16le").decode(e.data.subarray(32, 32 + len * 2));
  return [name, e.data.subarray(32 + len * 2)];
}

export function bootPolicy(evs, uki, dbCert) {
  const failures = [];
  const config = {};
  for (const e of evs) if (e.type === EV_EFI_VARIABLE_DRIVER_CONFIG) { const [n, v] = variable(e); config[n] = v; }
  const sb = config.SecureBoot;
  if (!(sb && sb.length === 1 && sb[0] === 1)) failures.push("Secure Boot is off, so a boot entry can replace the embedded command line");
  const auth = evs.filter((e) => e.type === EV_EFI_VARIABLE_AUTHORITY);
  if (!auth.length) failures.push("no image was verified by our key");
  else if (auth.some((e) => !contains(e.data, dbCert))) failures.push("an image was verified by a key other than ours");
  const images = evs.filter((e) => e.type === EV_EFI_BOOT_SERVICES_APPLICATION).map((e) => hex(e.digest));
  if (images.length !== 1 || images[0] !== uki) failures.push("more than the approved image was loaded");
  const allowed = new Set([EV_EFI_ACTION, EV_SEPARATOR, EV_EFI_GPT_EVENT, EV_EFI_BOOT_SERVICES_APPLICATION]);
  if (evs.some((e) => e.mr === 2 && !allowed.has(e.type))) failures.push("unexpected events in the boot stage register");
  return failures;
}

// -- binding ------------------------------------------------------------------

export async function bindResponse(requestId, responseHash, broker = "", tls = "") {
  if (tls) return sha384hex(`${requestId}:${responseHash}:${broker}:${tls}`);
  if (broker) return sha384hex(`${requestId}:${responseHash}:${broker}`);
  return sha384hex(`${requestId}:${responseHash}`);
}

function reportCanonical(a) {
  // AttestationReport.canonical(): every field but the signature, sorted, compact.
  return canonical({
    chip_id: a.chip_id, launch_measurement: a.launch_measurement, nonce: a.nonce,
    report_data: a.report_data, tcb_level: a.tcb_level,
  });
}

// -- the whole check ----------------------------------------------------------

/**
 * @param {string} proofText  the answer's structuredContent, as JSON text
 * @param {object} opts
 *   registry      parsed measurements.json
 *   intel         async (quoteBytes) => {status, advisory_ids}; throws if not genuine
 *   broker        the customer's key server fingerprint ("" to skip)
 *   nonce         the nonce the client sent ("" if none)
 *   releaseNames  optional map measurement -> image name
 */
export async function verifyProof(proofText, opts) {
  const checks = [];
  const add = (id, ok, title, detail) => checks.push({ id, ok, title, detail });
  let proof;
  try { proof = parseExact(proofText.trim()); } catch (e) {
    add("parse", false, "Readable proof", String(e.message)); return { ok: false, checks };
  }
  // A full answer also carries a text copy of the result, which is what most
  // agents read. The chip signs only the structured copy, so the text must say
  // the same thing or a pasted answer could pass with altered text.
  const envelope = proof && proof.result && proof.result.structuredContent ? proof.result : proof;
  const textCopies = Array.isArray(envelope && envelope.content)
    ? envelope.content.filter((c) => c && c.type === "text").map((c) => String(plain(c.text) ?? "")) : [];
  if (proof && proof.structuredContent) proof = proof.structuredContent;
  if (proof && proof.result && proof.result.structuredContent) proof = proof.result.structuredContent;
  const a = proof && proof.attestation;
  if (!a || typeof a.signature !== "string") {
    add("parse", false, "Readable proof", "No attestation found. Paste the structuredContent of a Sentinel answer.");
    return { ok: false, checks };
  }
  const att = Object.fromEntries(Object.entries(a).map(([k, v]) => [k, plain(v)]));
  let quote;
  try { quote = unhex(att.signature); } catch { add("parse", false, "Readable proof", "The quote is not hex."); return { ok: false, checks }; }
  if (quote.length < BODY + 584) { add("parse", false, "Readable proof", "This is not a TDX quote."); return { ok: false, checks }; }

  // 1. Intel
  let intelOk = false;
  try {
    const r = await opts.intel(quote);
    intelOk = ALLOWED_TCB.has(r.status);
    add("intel", intelOk, "Genuine Intel TDX, firmware up to date",
      intelOk ? `Intel's signature checks out. TCB status ${r.status}.`
              : `Intel signed it, but the TCB status is ${r.status}${r.advisory_ids?.length ? ` (${r.advisory_ids.join(", ")})` : ""}.`);
  } catch (e) {
    add("intel", false, "Genuine Intel TDX, firmware up to date", `Not a valid Intel TDX quote: ${e.message || e}`);
  }

  // 2. debug
  const attrs = new DataView(quote.buffer, quote.byteOffset).getBigUint64(BODY + TD_ATTRIBUTES, true);
  add("debug", (attrs & TD_DEBUG) === 0n, "The host cannot read this machine's memory",
    (attrs & TD_DEBUG) === 0n ? "The machine was not started in debug mode." : "Debug mode is on: the host can read and change its memory.");

  // 3. firmware
  const regs = registers(quote);
  const reg = opts.registry || {};
  const mrtdOk = (reg.tdx?.mrtd || []).includes(regs.MRTD);
  add("firmware", mrtdOk, "Approved machine firmware",
    `${mrtdOk ? "Firmware is on the approved list" : "Firmware is NOT on the approved list"}: ${regs.MRTD}`);

  // 4. image
  let uki = null;
  if (!proof.event_log) {
    add("image", null, "Approved Sentinel release",
      "This answer has no boot log, so which release booted cannot be shown from it alone. Miners from v5 include it.");
  } else {
    try {
      const evs = events(await inflate(b64(proof.event_log)));
      const replayed = await replay(evs);
      const bad = ["RTMR0", "RTMR1", "RTMR2"].filter((r) => replayed[r] !== regs[r]);
      if (bad.length) throw new Error(`the boot log does not match what the chip signed (${bad.join(", ")})`);
      const approved = new Set((reg.measurements || []).map((m) => m.measurement));
      const images = evs.filter((e) => e.type === EV_EFI_BOOT_SERVICES_APPLICATION).map((e) => hex(e.digest));
      uki = images.find((i) => approved.has(i)) || null;
      if (!uki) throw new Error(`the release that booted is not approved: ${images.map((i) => i.slice(0, 16)).join(", ") || "none"}`);
      const certs = reg.tdx?.secure_boot_db || [];
      let failures = ["no Secure Boot certificate is approved"];
      for (const c of certs) { failures = bootPolicy(evs, uki, unhex(c)); if (!failures.length) break; }
      if (failures.length) throw new Error(failures.join("; "));
      const name = (reg.measurements || []).find((m) => m.measurement === uki)?.image || "approved release";
      add("image", true, "Approved Sentinel release", `${name}, under Secure Boot with Sentinel's key. Measurement ${uki}`);
    } catch (e) {
      add("image", false, "Approved Sentinel release", String(e.message || e));
    }
  }

  // 5. this answer
  let tlsSigned = null;
  try {
    const rd = quote.subarray(BODY + REPORT_DATA, BODY + REPORT_DATA + 64);
    if (hex(await sha512(utf8(reportCanonical(a)))) !== hex(rd)) throw new Error("the report fields are not the ones the chip signed");
    if (!("result" in proof)) throw new Error("the proof has no result");
    const responseHash = await sha384hex(canonical(proof.result));
    if (responseHash !== plain(proof.response_hash)) throw new Error("the result does not match its hash; it was changed after it was signed");
    const rid = String(plain(proof.request_id) ?? ""), broker = String(plain(proof.broker) ?? ""), tls = String(plain(proof.tls) ?? "");
    if (att.report_data === await bindResponse(rid, responseHash, broker, tls)) tlsSigned = Boolean(tls);
    else if (tls && att.report_data === await bindResponse(rid, responseHash, broker)) tlsSigned = false;
    else throw new Error("the proof is for a different answer");
    if (uki && att.launch_measurement !== uki) throw new Error("the report names a different release than the one that booted");
    for (const text of textCopies) {
      let same = false;
      try { same = canonical(parseExact(text)) === canonical(proof.result); } catch { same = false; }
      if (!same) throw new Error("the text copy of the answer differs from the signed result");
    }
    add("answer", true, "This proof is for this exact answer", "The chip signed this result. Changing one character of it breaks the proof.");
  } catch (e) {
    add("answer", false, "This proof is for this exact answer", String(e.message || e));
  }

  // 6. key server
  const broker = String(plain(proof.broker) ?? "");
  if (!opts.broker) {
    add("broker", null, "The credential came from your key server",
      broker ? `Signed key server: ${broker}. Enter your key server's fingerprint to compare.` : "This answer used no key server.");
  } else {
    const ok = broker === opts.broker.trim().toLowerCase();
    add("broker", ok, "The credential came from your key server",
      ok ? `Key server ${broker}, the one you entered.` : `This answer came from key server ${broker || "none"}, not ${opts.broker.trim()}.`);
  }

  // 7. TLS
  const tls = String(plain(proof.tls) ?? "");
  if (!tls) add("tls", null, "Encrypted to inside the machine", "This answer names no TLS key.");
  else if (tlsSigned) add("tls", true, "Encrypted to inside the machine",
    `The chip signed the TLS key this answer was served under: ${tls}. If your client met that key, the connection ended inside the machine.`);
  else add("tls", null, "Encrypted to inside the machine",
    `The answer names TLS key ${tls}, but this release does not sign it (before v5). Your agent is still protected if it trusts only your key server's CA.`);

  // 8. freshness
  const nonce = String(plain(proof.nonce) ?? att.nonce ?? "");
  if (!opts.nonce) add("fresh", null, "Fresh", "Genuine, but freshness is not shown: send your own random nonce with the request and enter it here.");
  else {
    const ok = att.nonce === opts.nonce.trim() && nonce === att.nonce;
    add("fresh", ok, "Fresh", ok ? "Answers the nonce you sent, so it was made for your request." : "This answer was made for a different nonce.");
  }

  // Verified means the machine, the release and the answer are all shown. The
  // rest (your key server, freshness) depend on what the reader entered.
  const must = ["intel", "debug", "firmware", "image", "answer"];
  const ok = checks.every((c) => c.ok !== false) && must.every((id) => checks.find((c) => c.id === id)?.ok === true);
  return { ok, checks, release: uki, registers: regs };
}

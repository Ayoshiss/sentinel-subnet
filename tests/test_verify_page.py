"""
The browser verifier (web/verify) against the Python one, on a real TDX answer.

The page re-implements the validator's checks in JavaScript so a customer's
security reviewer can run them without trusting Sentinel. These tests keep the
two in step: the same captured answer must pass, and the same tampering must
fail at the same check. Needs Node 18 or later; skipped without it.
"""

import json
import pathlib
import shutil
import subprocess

import pytest

from sentinel.database import canonical

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "evidence" / "tdx-verity-image-2026-11-06"
NODE = shutil.which("node")


def _node_ok():
    if not NODE:
        return False
    out = subprocess.run([NODE, "--version"], capture_output=True, text=True).stdout
    return int(out.strip().lstrip("v").split(".")[0]) >= 18


pytestmark = pytest.mark.skipif(not _node_ok(), reason="needs Node 18+")


def run(cases=(), canonical_texts=()):
    proc = subprocess.run(
        [NODE, str(ROOT / "tests" / "verify_page_runner.mjs")],
        input=json.dumps({"cases": list(cases), "canonical": list(canonical_texts)}),
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@pytest.fixture(scope="module")
def real():
    probe = json.loads((EVIDENCE / "probe.json").read_text())
    meta = json.loads((EVIDENCE / "meta.json").read_text())
    registry = {
        "tdx": {"mrtd": [meta["mrtd"]], "secure_boot_db": [(EVIDENCE / "test-db.der").read_bytes().hex()]},
        "measurements": [{"image": "test image, 6 Nov 2026", "measurement": meta["uki"]["authenticode_sha384"]}],
    }
    proof = {**probe["response"], "nonce": probe["nonce"], "event_log": probe["health"]["event_log"]}
    return proof, registry, probe["nonce"]


def case(proof, registry, **kw):
    return {"proof": json.dumps(proof), "registry": registry, **kw}


def test_the_real_answer_passes_every_check(real):
    proof, registry, nonce = real
    (r,) = run([case(proof, registry, nonce=nonce)])["cases"]
    assert r["ok"] is True
    for check in ("intel", "debug", "firmware", "image", "answer", "fresh"):
        assert r["checks"][check][0] is True, (check, r["checks"][check])


def test_the_sample_shipped_with_the_page_is_that_answer(real):
    sample = json.loads((ROOT / "web" / "verify" / "sample.json").read_text())
    proof, registry, nonce = real
    assert sample["proof"] == proof and sample["registry"] == registry and sample["nonce"] == nonce


def test_tampering_fails_where_the_validator_fails(real):
    proof, registry, nonce = real
    changed = json.loads(json.dumps(proof))
    changed["result"]["rows"][0][0] = 2
    other_release = json.loads(json.dumps(registry))
    other_release["measurements"][0]["measurement"] = "00" * 48
    other_key = json.loads(json.dumps(registry))
    other_key["tdx"]["secure_boot_db"] = ["3082" + "11" * 300]
    other_fw = json.loads(json.dumps(registry))
    other_fw["tdx"]["mrtd"] = ["00" * 48]
    log_swapped = dict(proof, event_log=proof["event_log"][:-8] + "AAAAAAA=")
    results = run([
        case(changed, registry),
        case(proof, other_release),
        case(proof, other_key),
        case(proof, other_fw),
        case(proof, registry, nonce="ff" * 32),
        case(proof, registry, broker="ab" * 32),
        case(log_swapped, registry),
    ])["cases"]
    expect = ["answer", "image", "image", "firmware", "fresh", "broker", "image"]
    for r, check in zip(results, expect):
        assert r["ok"] is False, check
        assert r["checks"][check][0] is False, (check, r["checks"][check])


def test_a_pasted_answer_must_say_in_text_what_the_chip_signed(real):
    """Agents read the text copy; the chip signs the structured one. Pasted
    whole, an answer whose text was edited must not pass."""
    proof, registry, nonce = real

    def envelope(text):
        return {"jsonrpc": "2.0", "id": 1, "result": {
            "content": [{"type": "text", "text": text}], "structuredContent": proof, "isError": False}}

    honest = json.dumps(proof["result"], default=str)
    edited = honest.replace(json.dumps(proof["result"]["rows"][0][0]), "999999", 1)
    assert edited != honest
    ok, bad = run([case(envelope(honest), registry, nonce=nonce),
                   case(envelope(edited), registry, nonce=nonce)])["cases"]
    assert ok["ok"] is True
    assert bad["ok"] is False and bad["checks"]["answer"][0] is False
    assert "text copy" in bad["checks"]["answer"][1]


def test_an_answer_without_a_boot_log_is_not_called_verified(real):
    proof, registry, _ = real
    bare = {k: v for k, v in proof.items() if k != "event_log"}
    (r,) = run([case(bare, registry)])["cases"]
    assert r["checks"]["image"][0] is None
    assert r["ok"] is False


def test_the_page_hashes_results_exactly_as_the_miner_does():
    """The answer hash is over Python's json.dumps. Floats, escapes and key
    order must come out byte for byte the same, or honest answers would fail."""
    values = [
        {"b": 1, "a": [1.0, 2.5, -0.0, 1e100, 3], "c": None, "d": True},
        {"name": "Zoë", "emoji": "🙂", "ctl": "a\nb\t\"q\"\\", "nul": "\u0000", "del": "\u007f"},
        {"rows": [[1, "ada@example.com", "enterprise"]], "row_count": 1},
        {"é": 1, "e": 2, "🙂": 3, "￿": 4},
        [12345678901234567890, 0.1, 1.5e-7],
    ]
    texts = [json.dumps(v, default=str) for v in values]
    got = run(canonical_texts=texts)["canonical"]
    assert got == [canonical(v).decode() for v in values]

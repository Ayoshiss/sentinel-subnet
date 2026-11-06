"""
The miner's side of TDX: asking for a quote, and handing it to a broker.

Quote generation needs a TDX guest, so here configfs-tsm is stood in for by a
directory whose `outblob` is a real quote from hardware. What that tests is the
protocol around the kernel interface: the provider check, the generation check
and the REPORT_DATA check. Whether the kernel behaves as assumed is checked on
hardware, as the SEV-SNP guest code was.
"""

import base64
import json
import pathlib

import pytest

from sentinel.attestation import AttestationReport
from sentinel.kbs import (
    CredentialReleaseError,
    KeyBroker,
    ReleasePolicy,
    looks_like_sevsnp,
    looks_like_tdx,
    release_binding,
)
from sentinel.kbs_remote import BrokerHandler
from sentinel.serving.handler import Request
from sentinel.tdx import encode_event_log, guest

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "evidence" / "tdx-uki-secureboot-2026-11-06"
SEV_REPORT = ROOT / "tests" / "fixtures" / "sevsnp-report-20260831T055035Z.bin"
QUOTE = (EVIDENCE / "sb-A.quote").read_bytes()
NONCE = (EVIDENCE / "sb-A.nonce").read_bytes()
LOG = (EVIDENCE / "sb-A.ccel").read_bytes()
UKI = json.loads((EVIDENCE / "meta.json").read_text())["signed_uki"]["authenticode_sha384"]


def entry(tmp_path, *, provider="tdx_guest", quote=QUOTE, generations=("1", "1")):
    d = tmp_path / "report"
    d.mkdir()
    (d / "provider").write_text(provider + "\n")
    (d / "outblob").write_bytes(quote)
    reads = iter(generations)

    # `generation` is read twice, before and after the quote; serve the two
    # values in order so a test can make it move.
    gen = d / "generation"
    gen.write_text(next(reads))
    original = pathlib.Path.read_text

    def read_text(self, *a, **k):
        if self == gen:
            value = original(self, *a, **k)
            nxt = next(reads, None)
            if nxt is not None:
                gen.write_text(nxt)
            return value
        return original(self, *a, **k)

    return d, read_text


def test_a_quote_is_read_back_and_checked_against_the_request(tmp_path, monkeypatch):
    d, read_text = entry(tmp_path)
    monkeypatch.setattr(pathlib.Path, "read_text", read_text)
    assert guest.read_quote(d, NONCE) == QUOTE
    assert (d / "inblob").read_bytes() == NONCE


def test_a_quote_for_different_report_data_is_refused(tmp_path, monkeypatch):
    d, read_text = entry(tmp_path)
    monkeypatch.setattr(pathlib.Path, "read_text", read_text)
    with pytest.raises(guest.GuestError, match="REPORT_DATA"):
        guest.read_quote(d, bytes(64))


def test_a_concurrent_writer_is_detected(tmp_path, monkeypatch):
    d, read_text = entry(tmp_path, generations=("1", "2"))
    monkeypatch.setattr(pathlib.Path, "read_text", read_text)
    with pytest.raises(guest.GuestError, match="another writer"):
        guest.read_quote(d, NONCE)


def test_a_non_tdx_provider_is_refused(tmp_path, monkeypatch):
    d, read_text = entry(tmp_path, provider="sev_guest")
    monkeypatch.setattr(pathlib.Path, "read_text", read_text)
    with pytest.raises(guest.GuestError, match="provider"):
        guest.read_quote(d, NONCE)


def test_user_data_must_be_exactly_64_bytes(tmp_path):
    with pytest.raises(guest.GuestError, match="64 bytes"):
        guest.request_quote(b"short", root=str(tmp_path))


def test_the_platform_id_comes_from_the_pck_certificate():
    leaf = guest.pck_leaf(QUOTE)
    assert leaf.startswith(b"-----BEGIN CERTIFICATE-----")
    assert leaf.endswith(b"-----END CERTIFICATE-----")


def test_the_measurement_a_miner_reports_is_the_uki_in_its_event_log(tmp_path):
    (tmp_path / "ccel").write_bytes(LOG)
    silicon = guest.TdxSilicon(root=str(tmp_path), ccel=str(tmp_path / "ccel"))
    assert silicon.measurement == UKI
    assert silicon.event_log == LOG


# -- the broker -----------------------------------------------------------------

def test_quotes_and_sev_reports_are_told_apart_by_header():
    sev = SEV_REPORT.read_bytes().hex()
    assert looks_like_tdx(QUOTE.hex())
    assert not looks_like_sevsnp(QUOTE.hex()), "a quote is long enough to pass the old length test"
    assert looks_like_sevsnp(sev)
    assert not looks_like_tdx(sev)


class _Verifier:
    def __init__(self):
        self.calls = []

    def verify_signed_message(self, message, quote_hex, log):
        self.calls.append((message, quote_hex, log))


def _report(broker, resource="db", binding=None):
    return AttestationReport(
        chip_id="TDX-x", launch_measurement=UKI, tcb_level=0, nonce=broker.challenge(),
        report_data=binding or release_binding(resource), signature=QUOTE.hex(),
    )


def _broker(tdx=None):
    b = KeyBroker(policy=ReleasePolicy(approved_measurement=UKI), tdx=tdx)
    b.store_secret("db", "postgres://u:p@h/db")
    b.store_secret("other", "postgres://u:p@h/other")
    return b


def test_a_broker_without_a_tdx_verifier_refuses():
    b = _broker()
    with pytest.raises(CredentialReleaseError, match="no TDX verifier"):
        b.release("db", _report(b), event_log=LOG)


def test_a_quote_without_its_event_log_is_refused():
    b = _broker(_Verifier())
    with pytest.raises(CredentialReleaseError, match="without its event log"):
        b.release("db", _report(b))


def test_a_verified_quote_releases_and_the_log_reaches_the_verifier():
    v = _Verifier()
    b = _broker(v)
    report = _report(b)
    assert b.release("db", report, event_log=LOG).dsn.endswith("/db")
    assert v.calls == [(report.canonical(), QUOTE.hex(), LOG)]


def test_a_quote_bound_to_another_resource_is_refused():
    b = _broker(_Verifier())
    with pytest.raises(CredentialReleaseError, match="different resource"):
        b.release("other", _report(b, binding=release_binding("db")), event_log=LOG)


def test_the_remote_broker_carries_the_event_log():
    v = _Verifier()
    b = _broker(v)
    report = _report(b)
    body = json.dumps({
        "resource": "db",
        "attestation": report.__dict__,
        "event_log": base64.b64encode(encode_event_log(LOG)).decode(),
    }).encode()
    r = BrokerHandler(b).handle(Request("POST", "/release", {}, body))
    assert r.status == 200, r.payload
    assert v.calls[0][2] == LOG


def test_the_remote_broker_refuses_an_unreadable_event_log():
    b = _broker(_Verifier())
    body = json.dumps({
        "resource": "db", "attestation": _report(b).__dict__, "event_log": "not base64!",
    }).encode()
    assert BrokerHandler(b).handle(Request("POST", "/release", {}, body)).status == 400

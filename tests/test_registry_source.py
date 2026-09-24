"""Resolving approved measurements from chain, with fallback."""

import asyncio
import json

import pytest

from sentinel.registry import RegistryError, digest, manifest_line, parse
from sentinel.registry_source import RegistrySource

A = "aa" * 48
B = "bb" * 48
URL = "https://example.invalid/measurements.json"


def payload(*measurements):
    return {
        "version": 1,
        "netuid": 554,
        "measurements": [
            {"measurement": m, "platform": "gcp", "image": "img", "machine_type": "n2d"}
            for m in measurements
        ],
    }


class FakeChain:
    """A subtensor that returns whatever manifest the test wants."""

    def __init__(self, manifest=None, raises=False, hex_fields=False):
        self.manifest = manifest
        self.raises = raises
        self.hex_fields = hex_fields
        self.pinned_to = None

    def at(self, block):
        self.pinned_to = block
        return self

    def __init_subclass__(cls, **kw):  # pragma: no cover
        super().__init_subclass__(**kw)

    async def read(self, name, **params):
        if self.raises:
            raise ConnectionError("chain unreachable")
        if self.manifest is None:
            return None
        head, url = self.manifest
        if self.hex_fields:
            # The shape the real SDK returns: a 0x hex STRING, not bytes.
            return {"fields": [{f"Raw{len(head)}": "0x" + head.encode().hex()},
                               {f"Raw{len(url)}": "0x" + url.encode().hex()}]}
        return {"fields": [{f"Raw{len(head)}": head.encode()},
                           {f"Raw{len(url)}": url.encode()}]}


def manifest_for(body: dict, effective_from: int, url: str = URL):
    return manifest_line(digest(body), effective_from, url)


def run(coro):
    """The repo's convention: no async plugin, just drive the loop."""
    return asyncio.run(coro)


def source(fallback=frozenset(), **kw):
    return RegistrySource(554, "5Fake", fallback=fallback, **kw)


# --- the happy path -----------------------------------------------------------

def test_a_published_registry_replaces_the_local_flags(monkeypatch):
    body = payload(B)
    monkeypatch.setattr("sentinel.registry_source.fetch",
                        lambda url: json.dumps(body).encode())

    src = source(fallback=frozenset({A}))
    assert src.approved_at(100) == {A}, "starts on the operator's flags"

    assert run(src.refresh(FakeChain(manifest_for(body, effective_from=0))))
    assert src.approved_at(100) == {B}, "chain wins once it has something to say"
    assert not src.status().using_fallback


# --- effective_from is the whole point of the window --------------------------

def test_a_future_registry_waits_for_its_height(monkeypatch):
    """Every validator switches at the published block, not when it polled.

    A validator that promoted on discovery would diverge from one that had not
    polled yet, and under Yuma the one scoring an honest miner differently
    accrues no bond in it.
    """
    body = payload(B)
    monkeypatch.setattr("sentinel.registry_source.fetch",
                        lambda url: json.dumps(body).encode())

    src = source(fallback=frozenset({A}))
    run(src.refresh(FakeChain(manifest_for(body, effective_from=1_000))))

    assert src.approved_at(999) == {A}, "not yet"
    assert src.approved_at(1_000) == {B}, "now"
    assert src.approved_at(1_001) == {B}, "and it stays"


# --- failure must not stop scoring --------------------------------------------

def test_an_unreachable_chain_falls_back_rather_than_failing():
    """Halting would record zero for honest miners and cost this validator bond."""
    src = source(fallback=frozenset({A}))
    assert not run(src.refresh(FakeChain(raises=True)))
    assert src.approved_at(100) == {A}
    assert src.status().using_fallback


def test_a_failed_fetch_keeps_the_previous_list(monkeypatch):
    body = payload(B)
    monkeypatch.setattr("sentinel.registry_source.fetch",
                        lambda url: json.dumps(body).encode())
    src = source(fallback=frozenset({A}))
    run(src.refresh(FakeChain(manifest_for(body, effective_from=0))))
    assert src.approved_at(100) == {B}

    def boom(url):
        raise RegistryError("502 from the file host")

    monkeypatch.setattr("sentinel.registry_source.fetch", boom)
    newer = payload(A, B)
    run(src.refresh(FakeChain(manifest_for(newer, effective_from=0))))
    assert src.approved_at(100) == {B}, "the list that verified still stands"


def test_no_manifest_yet_is_not_an_error():
    """Before the registry goes live there is nothing committed, and that is fine."""
    src = source(fallback=frozenset({A}))
    assert not run(src.refresh(FakeChain(manifest=None)))
    assert src.approved_at(100) == {A}


# --- tampering is refused, loudly ---------------------------------------------

def test_a_file_that_does_not_match_the_chain_digest_is_refused(monkeypatch):
    """The digest is what lets the file be served from anywhere at all.

    Without this check, whoever hosts the file decides who may mine.
    """
    published = payload(B)
    tampered = payload(A, B)
    monkeypatch.setattr("sentinel.registry_source.fetch",
                        lambda url: json.dumps(tampered).encode())

    src = source(fallback=frozenset({A}))
    assert not run(src.refresh(FakeChain(manifest_for(published, effective_from=0))))
    assert src.approved_at(100) == {A}, "fell back rather than trusting the file"


def test_a_non_https_url_is_refused(monkeypatch):
    body = payload(B)
    src = source(fallback=frozenset({A}))
    run(src.refresh(FakeChain(manifest_for(body, 0, "http://example.invalid/x.json"))))
    assert src.approved_at(100) == {A}


# --- refusing to run with nothing at all --------------------------------------

def test_no_registry_and_no_flags_refuses_rather_than_approving_nothing():
    """Scoring every miner zero is worse than not starting."""
    src = source(fallback=frozenset())
    with pytest.raises(RegistryError, match="refuses to run"):
        src.approved_at(100)


# --- the read is pinned --------------------------------------------------------

def test_the_chain_read_is_pinned_to_a_block(monkeypatch):
    """Unpinned reads let two validators see different state across an update."""
    from sentinel.chain import read_manifest

    body = payload(B)
    chain = FakeChain(manifest_for(body, effective_from=7))
    run(read_manifest(chain, 554, "5Fake", block=8_000_000))
    assert chain.pinned_to == 8_000_000


# --- surviving a restart -------------------------------------------------------

def test_a_cached_registry_survives_a_restart(monkeypatch, tmp_path):
    """A restart during an outage must not silently drop to the flags."""
    body = payload(B)
    monkeypatch.setattr("sentinel.registry_source.fetch",
                        lambda url: json.dumps(body).encode())
    cache = tmp_path / "registry.json"

    first = source(fallback=frozenset({A}), cache_path=cache)
    run(first.refresh(FakeChain(manifest_for(body, effective_from=0))))
    assert first.approved_at(100) == {B}
    assert cache.exists()

    restarted = source(fallback=frozenset({A}), cache_path=cache)
    assert restarted.approved_at(100) == {B}, "came back on the cached list"


def test_hex_encoded_commitment_fields_are_decoded(monkeypatch):
    """The shape the real chain returns, which the first version got wrong.

    Published a genuine commitment and could not read it back: the SDK hands
    fields over as "0x7365..." hex strings rather than bytes, so the manifest
    parsed as nonsense. That reads as "nothing published", which is silent and
    keeps every validator on its own local list, which is the exact divergence
    the registry exists to prevent.
    """
    body = payload(B)
    monkeypatch.setattr("sentinel.registry_source.fetch",
                        lambda url: json.dumps(body).encode())

    src = source(fallback=frozenset({A}))
    chain = FakeChain(manifest_for(body, effective_from=0), hex_fields=True)
    assert run(src.refresh(chain)), "a hex-encoded manifest was not read"
    assert src.approved_at(100) == {B}

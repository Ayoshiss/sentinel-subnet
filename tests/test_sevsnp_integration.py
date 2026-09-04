"""
Verification against AMD's genuine certificate chain.

The unit tests use a synthetic root for speed. These fetch the real ARK and ASK
from AMD's Key Distribution Service and check our chain validation against the
actual trust anchor, the difference between "our code is self-consistent" and
"our code agrees with AMD".

Opt-in, because it needs the network and KDS is rate-limited:

    SENTINEL_NETWORK_TESTS=1 python -m pytest tests/test_sevsnp_integration.py -q

A genuine VCEK-signed report is no longer missing: one was captured from an AMD
EPYC 7B13 on 2026-08-31 and lives in `tests/fixtures/`, together with AMD's real
certificate chain. It is verified end to end in `tests/test_sevsnp.py`, offline
and without network access, so those checks are not gated behind this file.

What remains network-gated here is only what genuinely needs AMD reachable:
fetching certificates live from their Key Distribution Service.
"""

import os

import pytest

from sentinel.sevsnp import PRODUCTS, CertificateError, fetch_cert_chain
from sentinel.sevsnp.certs import CertChain

RUN = os.getenv("SENTINEL_NETWORK_TESTS") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not RUN, reason="set SENTINEL_NETWORK_TESTS=1 to reach AMD KDS"),
]


@pytest.fixture(scope="module")
def chains(tmp_path_factory):
    cache = tmp_path_factory.mktemp("amd-certs")
    return {p: fetch_cert_chain(p, cache_dir=cache) for p in PRODUCTS}


@pytest.mark.parametrize("product", PRODUCTS)
def test_real_amd_chain_verifies(chains, product):
    """AMD's published ARK is self-signed and has signed its ASK."""
    chains[product].verify_self()


@pytest.mark.parametrize("product", PRODUCTS)
def test_real_chain_names_match_the_product(chains, product):
    chain = chains[product]
    assert f"ARK-{product}" in chain.ark.subject.rfc4514_string()
    assert f"SEV-{product}" in chain.ask.subject.rfc4514_string()


def test_chains_are_distinct_per_product(chains):
    """Each EPYC generation has its own root, so a report must be checked
    against the chain for the product that produced it."""
    arks = {p: chains[p].ark.public_bytes_raw() if hasattr(chains[p].ark, "public_bytes_raw")
            else chains[p].ark.fingerprint(__import__("cryptography.hazmat.primitives.hashes",
                                                      fromlist=["SHA256"]).SHA256())
            for p in PRODUCTS}
    assert len(set(arks.values())) == len(PRODUCTS)


def test_cross_product_substitution_is_rejected(chains):
    """A Milan ASK under a Genoa root must not verify: this is the check that
    stops a report being validated against the wrong generation's trust root."""
    crossed = CertChain(product="x", ask=chains["Milan"].ask, ark=chains["Genoa"].ark)
    with pytest.raises(CertificateError, match="signature does not verify"):
        crossed.verify_self()


def test_chain_is_cached_after_first_fetch(tmp_path):
    """KDS is rate-limited; a validator checking many miners must not re-fetch."""
    fetch_cert_chain("Milan", cache_dir=tmp_path)
    cached = tmp_path / "Milan-cert_chain.pem"
    assert cached.exists() and cached.stat().st_size > 1000

    # Second call must be served from disk: break the network to prove it.
    import sentinel.sevsnp.certs as certs

    original = certs.urllib.request.urlopen
    certs.urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("cache miss: went to the network")
    )
    try:
        fetch_cert_chain("Milan", cache_dir=tmp_path).verify_self()
    finally:
        certs.urllib.request.urlopen = original

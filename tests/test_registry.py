"""The approved measurement registry."""

import json
import pathlib

import pytest

from sentinel.registry import (
    ApprovedImage,
    Registry,
    RegistryError,
    approved_for,
    digest,
    manifest_line,
    parse,
    parse_manifest,
)

A = "aa" * 48
B = "bb" * 48

REPO_FILE = pathlib.Path(__file__).parent.parent / "measurements.json"


def payload(*measurements):
    return {
        "version": 1,
        "netuid": 554,
        "measurements": [
            {
                "measurement": m,
                "platform": "gcp",
                "image": "ubuntu-2204-jammy-v20260826",
                "machine_type": "n2d-standard-2",
            }
            for m in measurements
        ],
    }


# --- the digest is the whole security property --------------------------------

def test_a_tampered_file_is_refused():
    """The digest comes from chain, so the file can be served from anywhere.

    If this check is ever weakened, whoever hosts the file decides who may mine.
    """
    good = payload(A)
    with pytest.raises(RegistryError, match="digest mismatch"):
        parse(json.dumps(payload(A, B)), expect_digest=digest(good))


def test_reformatting_does_not_change_the_digest():
    """Indentation, key order and trailing newlines must not orphan validators.

    A digest that moved when someone ran a formatter would mean the next tidy-up
    commit silently refused every miner.
    """
    p = payload(A)
    pretty = json.dumps(p, indent=4, sort_keys=False) + "\n\n"
    assert parse(pretty, expect_digest=digest(p)).measurements == {A}


def test_the_digest_ignores_the_schedule():
    """Republishing at a new height must not change what validators fetch.

    If the height were covered, the file and the commitment would have to be
    updated in lockstep, and the wrong order points every validator at a digest
    that does not match the file they download.
    """
    p = payload(A)
    assert digest(p) == digest(p | {"effective_from": 999_999})


def test_a_matching_file_parses():
    p = payload(A, B)
    assert parse(json.dumps(p), expect_digest=digest(p)).measurements == {A, B}


# --- refusing rather than opening up -------------------------------------------

def test_an_empty_registry_is_refused():
    """Approving nothing must not be read as approving anything."""
    with pytest.raises(RegistryError, match="approves nothing"):
        parse(json.dumps(payload()))


def test_a_future_version_is_refused():
    p = payload(A) | {"version": 99}
    with pytest.raises(RegistryError, match="unsupported registry version"):
        parse(json.dumps(p))


@pytest.mark.parametrize("bad", ["", "abc", "zz" * 48, "aa" * 47])
def test_a_measurement_that_is_not_48_bytes_is_refused(bad):
    with pytest.raises(RegistryError, match="96 hex characters"):
        ApprovedImage(measurement=bad, platform="gcp", image="x", machine_type="y")


# --- effective_from, the publisher's half of synchronisation -------------------

def test_a_registry_does_not_apply_before_its_height():
    """Published ahead of time, applied at one height by everyone.

    Without this, a validator that polls early switches early and diverges from
    every validator that has not polled yet, which costs it bond in the miners
    it scores differently.
    """
    future = parse(json.dumps(payload(B)), effective_from=1_000)
    assert not future.active_at(999)
    assert future.active_at(1_000)

    with pytest.raises(RegistryError, match="no registry is in effect"):
        approved_for([future], 999)


def test_overlapping_registries_approve_the_union():
    """The migration window: old and new both valid while miners move.

    This is the case that broke in production. A rebuild changed the measurement
    and an independent validator kept scoring the miner zero until it was told
    the new value by hand.
    """
    old = parse(json.dumps(payload(A)), effective_from=0)
    new = parse(json.dumps(payload(B)), effective_from=1_000)

    assert approved_for([old, new], 999) == {A}
    assert approved_for([old, new], 1_000) == {A, B}


# --- what goes on chain ---------------------------------------------------------

def test_the_manifest_fits_in_a_commitment_field():
    """128 bytes per field is the chain's limit, not a style choice."""
    head, url = manifest_line(
        digest(payload(A)), 8_073_000,
        "https://raw.githubusercontent.com/Ayoshiss/sentinel-subnet/main/measurements.json",
    )
    assert len(head) <= 128 and len(url) <= 128
    assert parse_manifest(head, url) == (
        8_073_000, digest(payload(A)),
        "https://raw.githubusercontent.com/Ayoshiss/sentinel-subnet/main/measurements.json",
    )


def test_an_oversized_url_is_refused_rather_than_truncated():
    with pytest.raises(RegistryError, match="does not fit"):
        manifest_line(digest(payload(A)), 1, "https://example.com/" + "x" * 200)


# --- the file this repository actually ships ------------------------------------

def test_the_published_registry_parses_and_holds_the_live_measurement():
    """The file is part of the protocol, so a typo in it is an outage."""
    reg = parse(REPO_FILE.read_text())
    assert reg.netuid == 554
    live = "ccdc5cf01ba25526bd65503d95931b787b4385a3277cfe4448addf9c3e894948ae8cf7b099620e3e22717de2fb5d26fa"
    assert live in reg.measurements
    # Every entry carries the recipe that produced it, so a reader can rebuild
    # that configuration and check the value rather than taking it on trust.
    for image in reg.images:
        assert image.image and image.machine_type and image.platform

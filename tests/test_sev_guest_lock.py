"""
The lock that stops the VMPCK being bricked.

Requests to the SEV firmware are encrypted under a key carrying a sequence
counter. Two in flight at once desync it, and the kernel then permanently
disables the key rather than risk reusing an IV, so the guest cannot attest
again until it reboots. That happened on 2026-09-24, triggered by an operator
running --print-measurement while the service was serving.

The code fix landed then. On 2026-10-04 the live miner turned out to have been
running without the lock the whole time anyway, because the systemd unit set
ProtectSystem=strict without granting /run/lock, the lock file could not be
created, and the fallback path said nothing. The mechanism was correct and
inactive, which is the same class of mistake as a broker that verifies its own
attestation.

So these tests cover the lock, and also the unit file, because the unit is where
it was actually broken.
"""

import os
import pathlib
import subprocess
import sys
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
UNIT = REPO / "deploy" / "sentinel-miner.service"

needs_fcntl = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file locks")


# --- the defect that hid for weeks -------------------------------------------

def test_the_miner_unit_grants_write_access_to_the_lock_directory():
    """ProtectSystem=strict makes /run/lock read-only unless this says otherwise.

    This is the test that would have caught the production outage. Without it,
    the lock silently does not exist and concurrent attestation bricks the chip.
    """
    text = UNIT.read_text()
    assert "ProtectSystem=strict" in text, "unit no longer hardens the filesystem"

    paths = [
        line.split("=", 1)[1].split()
        for line in text.splitlines()
        if line.startswith("ReadWritePaths=")
    ]
    granted = {p for entry in paths for p in entry}
    assert "/run/lock" in granted, (
        "the SEV guest lock lives in /run/lock, and ProtectSystem=strict makes it "
        "read-only. Without it in ReadWritePaths the lock cannot be created, "
        "cross-process safety is lost, and a second attesting process will "
        "permanently disable the VMPCK."
    )


def test_the_lock_path_is_inside_a_directory_the_unit_grants():
    """Keeps the two in step if either is moved."""
    from sentinel.sevsnp.guest import SEV_GUEST_LOCK

    # /var/lock is the conventional symlink to /run/lock, so accept either.
    assert SEV_GUEST_LOCK.startswith(("/var/lock/", "/run/lock/")), SEV_GUEST_LOCK
    granted = UNIT.read_text()
    assert "/run/lock" in granted


@needs_fcntl
def test_an_unwritable_lock_directory_is_reported_not_swallowed(monkeypatch, caplog):
    """Degrading quietly is what let this reach production.

    The fallback is deliberate, a miner that cannot lock must still attest, but
    it degrades to the precise condition that kills the chip, so it has to say
    so where an operator will see it.
    """
    import logging

    from sentinel.sevsnp import guest

    monkeypatch.setattr(guest, "SEV_GUEST_LOCK", "/proc/definitely-not-writable/x")
    monkeypatch.setattr(guest, "_LOCK_WARNED", False)

    with caplog.at_level(logging.ERROR, logger="sentinel.sevsnp.guest"):
        with guest.sev_guest_exclusive():
            pass

    assert caplog.records, "an unwritable lock directory logged nothing at all"
    message = caplog.records[0].getMessage()
    assert "VMPCK" in message
    assert "ReadWritePaths" in message, "the message should name the actual fix"


@needs_fcntl
def test_the_warning_is_emitted_once_not_per_request(monkeypatch, caplog):
    """A per-request error would bury the journal and get filtered out."""
    import logging

    from sentinel.sevsnp import guest

    monkeypatch.setattr(guest, "SEV_GUEST_LOCK", "/proc/definitely-not-writable/x")
    monkeypatch.setattr(guest, "_LOCK_WARNED", False)

    with caplog.at_level(logging.ERROR, logger="sentinel.sevsnp.guest"):
        for _ in range(5):
            with guest.sev_guest_exclusive():
                pass

    assert len(caplog.records) == 1, f"logged {len(caplog.records)} times"


# --- the lock itself ---------------------------------------------------------

@needs_fcntl
def test_the_lock_serialises_two_separate_processes(tmp_path):
    """Two processes, overlapping windows, and the overlap must not happen.

    A threading lock would pass nothing here, which is the point: the caller
    that bricked the chip was a separate process, not a thread.
    """
    lock = tmp_path / "sev.lock"
    log = tmp_path / "order.txt"

    program = f'''
import sys, time
sys.path.insert(0, {str(REPO)!r})
from sentinel.sevsnp import guest
guest.SEV_GUEST_LOCK = {str(lock)!r}
with guest.sev_guest_exclusive():
    with open({str(log)!r}, "a") as fh:
        fh.write(f"enter {{sys.argv[1]}}\\n")
    # Long enough that unserialised processes would certainly interleave.
    time.sleep(0.5)
    with open({str(log)!r}, "a") as fh:
        fh.write(f"leave {{sys.argv[1]}}\\n")
'''
    script = tmp_path / "hold.py"
    script.write_text(program)

    first = subprocess.Popen([sys.executable, str(script), "A"])
    time.sleep(0.1)  # let A take the lock
    second = subprocess.Popen([sys.executable, str(script), "B"])
    assert first.wait(timeout=30) == 0
    assert second.wait(timeout=30) == 0

    lines = log.read_text().split()
    # Flattened, the sequence must be enter/leave/enter/leave. Any interleaving
    # means both processes were talking to the firmware at once.
    events = log.read_text().strip().splitlines()
    assert len(events) == 4, events
    assert events[0].startswith("enter")
    assert events[1].startswith("leave")
    assert events[0].split()[1] == events[1].split()[1], f"interleaved: {events}"
    assert events[2].startswith("enter")
    assert events[3].startswith("leave")
    assert lines, lines


@needs_fcntl
def test_the_lock_is_released_even_when_the_body_raises(tmp_path, monkeypatch):
    """A failed attestation must not keep the channel locked forever."""
    from sentinel.sevsnp import guest

    monkeypatch.setattr(guest, "SEV_GUEST_LOCK", str(tmp_path / "sev.lock"))

    with pytest.raises(RuntimeError):
        with guest.sev_guest_exclusive():
            raise RuntimeError("attestation blew up")

    # If the lock leaked, this would block forever rather than returning.
    with guest.sev_guest_exclusive():
        pass

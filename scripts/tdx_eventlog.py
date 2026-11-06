"""
Explain a TDX quote's registers from the firmware event log, offline.

A quote says what RTMR0-2 are; the CC event log (the ACPI CCEL table) says why.
Replaying the log's SHA-384 digests must land on exactly the values the chip
signed, and once it does, every input to a register can be named. Two of those
inputs, the UKI and the kernel inside it, are Authenticode hashes that anyone
can compute from the file without booting it, which is what makes an approved
measurement checkable from source rather than taken on trust.

    python scripts/tdx_eventlog.py replay QUOTE CCEL
    python scripts/tdx_eventlog.py image UKI.efi
    python scripts/tdx_eventlog.py policy QUOTE CCEL UKI_AUTHENTICODE DB.der
"""

from __future__ import annotations

import hashlib
import struct
import sys
import uuid
from dataclasses import dataclass

#: Offsets from the start of the TD quote body, which follows a 48-byte header.
BODY = 48
REGISTERS = {"MRTD": 136, "RTMR0": 328, "RTMR1": 376, "RTMR2": 424, "RTMR3": 472}
REPORT_DATA = 520

EV_NO_ACTION = 0x3
EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001
EV_EFI_VARIABLE_BOOT = 0x80000002
EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003
EV_EFI_GPT_EVENT = 0x80000006
EV_EFI_ACTION = 0x80000007
EV_SEPARATOR = 0x4
EV_EFI_VARIABLE_AUTHORITY = 0x800000E0

_DIGEST_SIZES = {0x4: 20, 0xB: 32, 0xC: 48, 0xD: 64}
_SHA384 = 0xC


def registers(quote: bytes) -> dict[str, str]:
    return {k: quote[BODY + o : BODY + o + 48].hex() for k, o in REGISTERS.items()}


@dataclass(frozen=True)
class Event:
    #: CC measurement register index: 0 is MRTD, 1-4 are RTMR0-3.
    mr: int
    type: int
    digest: bytes
    data: bytes

    @property
    def rtmr(self) -> int:
        return self.mr - 1

    def variable(self) -> tuple[str, bytes]:
        """(name, value) for an EFI variable event."""
        name_len = struct.unpack_from("<Q", self.data, 16)[0]
        name = self.data[32 : 32 + name_len * 2].decode("utf-16le")
        return name, self.data[32 + name_len * 2 :]


def events(log: bytes) -> list[Event]:
    """Parse a crypto-agile event log, skipping the SHA-1 format header event."""
    off = 32 + struct.unpack_from("<I", log, 28)[0]
    out = []
    while off + 12 <= len(log):
        mr, etype, count = struct.unpack_from("<III", log, off)
        if mr == 0xFFFFFFFF or (mr == 0 and etype == 0) or count > 8:
            break
        p, digest = off + 12, b""
        for _ in range(count):
            alg = struct.unpack_from("<H", log, p)[0]
            size = _DIGEST_SIZES[alg]
            if alg == _SHA384:
                digest = log[p + 2 : p + 2 + size]
            p += 2 + size
        size = struct.unpack_from("<I", log, p)[0]
        out.append(Event(mr, etype, digest, log[p + 4 : p + 4 + size]))
        off = p + 4 + size
    return out


def replay(evs: list[Event]) -> dict[str, str]:
    mrs = {i: bytes(48) for i in range(1, 5)}
    for e in evs:
        if e.type != EV_NO_ACTION and e.mr in mrs:
            mrs[e.mr] = hashlib.sha384(mrs[e.mr] + e.digest).digest()
    return {f"RTMR{i - 1}": v.hex() for i, v in mrs.items()}


def boot_policy(evs: list[Event], *, uki: str, db_cert: bytes) -> list[str]:
    """Reasons to refuse this boot; empty means it passes.

    Checked over the replayed log rather than by pinning register values,
    because the registers also absorb things that do not matter: boot entries
    an operator is free to have, and the fixed action strings the firmware logs
    for each refused boot attempt. Call only after `replay` has matched the
    quote, otherwise the log proves nothing.
    """
    failures = []
    config = {e.variable()[0]: e.variable()[1] for e in evs if e.type == EV_EFI_VARIABLE_DRIVER_CONFIG}
    if config.get("SecureBoot") != b"\x01":
        failures.append("Secure Boot is off, so a boot entry can replace the embedded command line")
    authorities = [e for e in evs if e.type == EV_EFI_VARIABLE_AUTHORITY]
    if not authorities:
        failures.append("no image was verified by our key")
    elif any(db_cert not in e.data for e in authorities):
        failures.append("an image was verified by a key other than ours")
    images = [e.digest.hex() for e in evs if e.type == EV_EFI_BOOT_SERVICES_APPLICATION]
    if images != [uki]:
        failures.append(f"loaded images {[i[:16] for i in images]} are not exactly the approved image")
    allowed = {EV_EFI_ACTION, EV_SEPARATOR, EV_EFI_GPT_EVENT, EV_EFI_BOOT_SERVICES_APPLICATION}
    unexpected = {hex(e.type) for e in evs if e.rtmr == 1 and e.type not in allowed}
    if unexpected:
        failures.append(f"unexpected RTMR1 events {sorted(unexpected)}")
    return failures


def gpt(e: Event) -> dict:
    """Disk GUID, last usable LBA and partition extents from an EFI_GPT_EVENT."""
    d = e.data
    entry_size = struct.unpack_from("<I", d, 84)[0]
    count = struct.unpack_from("<Q", d, 92)[0]
    parts = []
    for i in range(count):
        entry = d[100 + i * entry_size : 100 + (i + 1) * entry_size]
        first, last = struct.unpack_from("<QQ", entry, 32)
        parts.append((str(uuid.UUID(bytes_le=entry[16:32])), first, last))
    return {
        "disk_guid": str(uuid.UUID(bytes_le=d[56:72])),
        "last_usable_lba": struct.unpack_from("<Q", d, 48)[0],
        "partitions": parts,
    }


def _section(pe: bytes, name: str) -> bytes:
    hdr = struct.unpack_from("<I", pe, 0x3C)[0]
    nsec = struct.unpack_from("<H", pe, hdr + 6)[0]
    table = hdr + 24 + struct.unpack_from("<H", pe, hdr + 20)[0]
    for i in range(nsec):
        s = table + 40 * i
        if pe[s : s + 8].rstrip(b"\0").decode() == name:
            vsize = struct.unpack_from("<I", pe, s + 8)[0]
            rsize, rptr = struct.unpack_from("<II", pe, s + 16)
            return pe[rptr : rptr + min(vsize, rsize)]
    raise KeyError(name)


def authenticode(pe: bytes) -> str:
    """SHA-384 Authenticode digest: what UEFI measures when it loads an image."""
    hdr = struct.unpack_from("<I", pe, 0x3C)[0]
    opt = hdr + 24
    plus = struct.unpack_from("<H", pe, opt)[0] == 0x20B
    checksum = opt + 64
    cert_dir = opt + (112 if plus else 96) + 4 * 8
    headers = struct.unpack_from("<I", pe, opt + 60)[0]
    cert_off, cert_size = struct.unpack_from("<II", pe, cert_dir)
    h = hashlib.sha384()
    h.update(pe[:checksum])
    h.update(pe[checksum + 4 : cert_dir])
    h.update(pe[cert_dir + 8 : headers])
    nsec = struct.unpack_from("<H", pe, hdr + 6)[0]
    table = opt + struct.unpack_from("<H", pe, hdr + 20)[0]
    sections = []
    for i in range(nsec):
        rsize, rptr = struct.unpack_from("<II", pe, table + 40 * i + 16)
        if rsize:
            sections.append((rptr, rsize))
    done = headers
    for ptr, size in sorted(sections):
        h.update(pe[ptr : ptr + size])
        done = max(done, ptr + size)
    end = len(pe) - (cert_size if cert_off else 0)
    if end > done:
        h.update(pe[done:end])
    return h.hexdigest()


def image(uki: bytes) -> dict[str, str]:
    """The two digests a UKI contributes to RTMR1, plus its embedded command line."""
    return {
        "uki": authenticode(uki),
        "kernel": authenticode(_section(uki, ".linux")),
        "cmdline": _section(uki, ".cmdline").rstrip(b"\0\n").decode(),
    }


def _main(argv: list[str]) -> None:
    if argv[:1] == ["replay"]:
        quote, log = open(argv[1], "rb").read(), open(argv[2], "rb").read()
        evs = events(log)
        signed, replayed = registers(quote), replay(evs)
        for e in evs:
            if e.type in (EV_EFI_VARIABLE_DRIVER_CONFIG, EV_EFI_VARIABLE_BOOT):
                print(f"RTMR{e.rtmr} variable {e.variable()[0]}")
            elif e.type == EV_EFI_BOOT_SERVICES_APPLICATION:
                print(f"RTMR{e.rtmr} image    {e.digest.hex()[:32]}")
            elif e.type == EV_EFI_GPT_EVENT:
                print(f"RTMR{e.rtmr} gpt      {gpt(e)}")
        for k in ("RTMR0", "RTMR1", "RTMR2"):
            ok = "matches quote" if signed[k] == replayed[k] else "MISMATCH"
            print(f"{k} {replayed[k][:32]}  {ok}")
    elif argv[:1] == ["policy"]:
        quote, log = open(argv[1], "rb").read(), open(argv[2], "rb").read()
        evs = events(log)
        signed, replayed = registers(quote), replay(evs)
        if any(signed[k] != replayed[k] for k in ("RTMR0", "RTMR1", "RTMR2")):
            sys.exit("event log does not replay to the quote")
        failures = boot_policy(evs, uki=argv[3], db_cert=open(argv[4], "rb").read())
        print("\n".join(failures) or "pass")
    elif argv[:1] == ["image"]:
        for k, v in image(open(argv[1], "rb").read()).items():
            print(f"{k:8} {v}")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    _main(sys.argv[1:])

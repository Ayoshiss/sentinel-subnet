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

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sentinel.tdx.eventlog import (  # noqa: E402
    EV_EFI_BOOT_SERVICES_APPLICATION,
    EV_EFI_GPT_EVENT,
    EV_EFI_VARIABLE_BOOT,
    EV_EFI_VARIABLE_DRIVER_CONFIG,
    boot_policy,
    events,
    gpt,
    image,
    registers,
    replay,
)


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

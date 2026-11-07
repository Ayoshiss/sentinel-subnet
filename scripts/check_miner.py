#!/usr/bin/env python3
"""
Check a Sentinel endpoint the way a customer should: is it running an approved
image, on genuine Intel TDX, and answering from MY key server?

    python scripts/check_miner.py --url https://sentinel.example:8091 \
        --miner-hotkey 5... --expected-broker <fingerprint from run_broker.py>

The first run creates a checking key in --key-file and prints its address. Add
that address to the miner's `allow_hotkey` list, so the miner answers this
check. It is a local key, never registered anywhere.

Approved images, TD firmware and the Secure Boot certificate come from the
registry file (measurements.json from the repo by default), so this checks the
same values the subnet's validators do. Exit status 0 means verified.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def checking_key(path: pathlib.Path):
    from bittensor.sp_core import Keypair

    if path.exists():
        return Keypair.create_from_mnemonic(path.read_text().strip())
    path.parent.mkdir(parents=True, exist_ok=True)
    mnemonic = Keypair.generate_mnemonic()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(mnemonic + "\n")
    key = Keypair.create_from_mnemonic(mnemonic)
    print(f"created a checking key. Add this to the miner's allow_hotkey: {key.ss58_address}")
    return key


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", required=True, help="the miner's base URL")
    p.add_argument("--miner-hotkey", required=True, help="the miner's hotkey address")
    p.add_argument("--expected-broker", required=True,
                   help="your key server's fingerprint, as run_broker.py logs it at start")
    p.add_argument("--registry", default=str(ROOT / "measurements.json"),
                   help="registry file with the approved image, firmware and certificate")
    p.add_argument("--key-file", default="~/.config/sentinel/checking-key",
                   help="where the local checking key lives")
    args = p.parse_args(argv)

    from sentinel.registry import RegistryError, parse
    from sentinel.validating import MinerEvaluator, MinerTarget

    try:
        registry = parse(pathlib.Path(args.registry).read_text())
    except (OSError, RegistryError) as exc:
        print(f"cannot read the registry: {exc}", file=sys.stderr)
        return 2
    if not registry.tdx_mrtd:
        print("the registry has no tdx section, so nothing can be checked on TDX", file=sys.stderr)
        return 2

    key = checking_key(pathlib.Path(args.key_file).expanduser())
    evaluator = MinerEvaluator(
        key, registry.measurements,
        tdx_mrtd=registry.tdx_mrtd, tdx_db_cert=registry.tdx_db_certs,
        expected_broker=args.expected_broker.lower(),
    )
    (outcome,) = evaluator.evaluate_round(
        [MinerTarget(uid=0, hotkey_ss58=args.miner_hotkey, base_url=args.url.rstrip("/"))]
    )
    print(json.dumps({
        "verified": outcome.verified,
        "attestation": outcome.scores.attestation,
        "correctness": outcome.scores.correctness,
        "error": outcome.error,
    }, indent=2))
    return 0 if outcome.verified else 1


if __name__ == "__main__":
    raise SystemExit(main())

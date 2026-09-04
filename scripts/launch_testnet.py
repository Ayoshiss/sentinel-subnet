"""
Milestone 5, launch Sentinel on public Bittensor testnet.

Run:  python scripts/launch_testnet.py --check          # dry run, spends nothing
      python scripts/launch_testnet.py --create         # create + start the subnet
      python scripts/launch_testnet.py --netuid N --register

Encodes what the local chain taught us, so none of it has to be rediscovered
against real TAO:

    * burned_register is MEV-shielded, and the shielded inner extrinsic expires
      if you retry too fast. Attempts are spaced ~30s.
    * Never set max_spend_tao for registration, the cost cannot be bounded in
      advance and the policy blocks the call outright.
    * A new subnet's alpha pool is tiny, so stake SMALL. τ500 blew the slippage
      guard locally; τ1 went through.
    * The chain rejects loopback axons. Publish an address peers can reach.
    * ServeAxon is rate-limited to one call per ~50 blocks.

The coldkey here is the real, encrypted one, so operations prompt for a
password. That is deliberate: this wallet holds testnet value and will hold
mainnet value, and it is never automated against.
"""

import argparse
import asyncio
import logging
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import bittensor as bt

ENDPOINT = "test"
BTCLI = str(pathlib.Path(__file__).resolve().parent.parent / ".venv" / "bin" / "btcli")


def run_btcli(args: list[str]) -> tuple[bool, str]:
    """btcli handles MEV-shielded submissions correctly; hand-rolled execute()
    gets the nonce sequencing wrong, so registration goes through the CLI."""
    proc = subprocess.run([BTCLI, *args], capture_output=True, text=True)
    out = (proc.stdout + proc.stderr).strip()
    return ("success" in out.lower() and "false" not in out.lower().split("success")[1][:10]), out


async def check(wallet_name: str) -> None:
    """Read-only. Spends nothing, prompts for nothing."""
    w = bt.Wallet(name=wallet_name)
    cold = w.coldkeypub.ss58_address
    print(f"  coldkey  : {cold}")

    async with bt.Subtensor(ENDPOINT) as st:
        bal = await st.read("balance", coldkey_ss58=cold)
        print(f"  balance  : {bal}")
        print()
        for hk in ("miner", "validator"):
            try:
                addr = bt.Wallet(name=wallet_name, hotkey=hk).hotkey.ss58_address
                print(f"  hotkey {hk:10}: {addr}")
            except Exception:
                print(f"  hotkey {hk:10}: MISSING: btcli wallet new-hotkey "
                      f"--wallet {wallet_name} --wallet-hotkey {hk}")
        print()
        if bal.tao < 5:
            print("  ⚠ balance is low; creating a subnet costs τ1 plus fees and stake")
        else:
            print("  ✓ funded well enough to create a subnet and register")


def create(wallet_name: str) -> None:
    """Create the subnet, then start it. τ1 plus fees."""
    print("\n[1] creating subnet (τ1)")
    ok, out = run_btcli(["subnets", "create", "--network", ENDPOINT,
                         "-w", wallet_name, "-H", "validator", "--yes", "--json"])
    print("  " + out[-400:])
    if not ok:
        print("\n  creation failed: not starting. Re-run once resolved.")
        return

    netuid = _extract_netuid(out)
    if netuid is None:
        print("\n  could not read the netuid from the response; check manually.")
        return

    print(f"\n[2] starting subnet {netuid}")
    time.sleep(15)  # let the creation settle before the start call
    ok, out = run_btcli(["sudo", "start", "--netuid", str(netuid), "--network", ENDPOINT,
                         "-w", wallet_name, "-H", "validator", "--yes", "--json"])
    print("  " + out[-300:])
    print(f"\n  NETUID {netuid}, record this. It is the number for the review.")


def register(wallet_name: str, netuid: int) -> None:
    """Register both hotkeys, spacing retries for the MEV shield."""
    for hotkey in ("miner", "validator"):
        print(f"\n[register] {hotkey} on netuid {netuid}")
        for attempt in range(1, 5):
            ok, out = run_btcli(["subnets", "register", "--network", ENDPOINT,
                                 "-w", wallet_name, "-H", hotkey,
                                 "--netuid", str(netuid), "--yes", "--json"])
            print(f"  attempt {attempt}: {'ok' if ok else 'failed'}")
            if ok:
                break
            if "era" in out.lower() or "expired" in out.lower():
                print("    (shielded extrinsic expired: spacing and retrying)")
            time.sleep(30)
        else:
            print(f"  {hotkey} did not register after 4 attempts; see output above")


def _extract_netuid(out: str) -> int | None:
    import json
    import re

    for match in re.finditer(r"\{.*\}", out, re.S):
        try:
            data = json.loads(match.group())
        except json.JSONDecodeError:
            continue
        netuid = (data.get("data") or {}).get("netuid")
        if netuid is not None:
            return int(netuid)
    match = re.search(r"[Ss]ubnet (\d+) registered", out)
    return int(match.group(1)) if match else None


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--wallet", default="sentinel")
    p.add_argument("--check", action="store_true", help="read-only status")
    p.add_argument("--create", action="store_true", help="create and start the subnet")
    p.add_argument("--register", action="store_true", help="register both hotkeys")
    p.add_argument("--netuid", type=int, help="required with --register")
    args = p.parse_args()

    logging.basicConfig(level=logging.WARNING)
    print("Sentinel: public testnet")
    print("=" * 70)

    if args.create:
        create(args.wallet)
    elif args.register:
        if args.netuid is None:
            sys.exit("--register needs --netuid")
        register(args.wallet, args.netuid)
    else:
        asyncio.run(check(args.wallet))

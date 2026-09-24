"""
Publish the approved measurement registry on chain.

    python scripts/publish_measurements.py --effective-from <block>
    python scripts/publish_measurements.py --effective-from <block> --submit

Until this existed, a validator learned which measurements were approved by
somebody typing a value into a chat message. That is fine with one validator and
wrong with two: hold different lists and you score the same miner differently,
and the validator that withheld weight from an honest miner accrues no bond in
it, so it misses the dividend that miner earns. Bonds are an exponential moving
average, so the loss outlasts the mistake.

What goes on chain is a manifest: a version, the block from which it applies, a
digest of the list, and where to fetch it. Two commitment fields of at most 128
bytes each. The list itself is a file, because commitments cap out around 1.5KB
and the larger field type is dropped on read by a bug in the SDK.

Publishing is deliberately two steps. A dry run prints exactly what would be
committed and changes nothing; `--submit` sends it. Getting this wrong points
every validator at a list that does not exist, so it should be hard to do by
accident.
"""

import argparse
import asyncio
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sentinel.registry import digest, manifest_line, parse

DEFAULT_FILE = pathlib.Path(__file__).resolve().parent.parent / "measurements.json"
DEFAULT_URL = (
    "https://raw.githubusercontent.com/Ayoshiss/sentinel-subnet/main/measurements.json"
)

#: How far ahead a new registry takes effect, in blocks. One tempo on 554 is 360
#: blocks, about 72 minutes. Validators poll on their own schedule, so the delay
#: has to be long enough that every one of them has read the new manifest before
#: it applies. Publishing with a height that has already passed means validators
#: switch as they notice, which is the divergence this is meant to prevent.
DEFAULT_LEAD_BLOCKS = 720


async def publish(args) -> int:
    import bittensor as bt

    gen = __import__("bittensor._generated.calls", fromlist=["calls"])

    raw = pathlib.Path(args.file).read_text()
    payload = json.loads(raw)

    async with bt.Subtensor(args.endpoint) as st:
        head_block = int((await st.read("metagraph", netuid=args.netuid))["block"])
        effective = args.effective_from or head_block + DEFAULT_LEAD_BLOCKS
        # The digest covers the list only, never the schedule, so republishing
        # at a new height does not change what validators fetch.
        registry = parse(raw, effective_from=effective)
        reg_digest = digest(payload)
        head, url = manifest_line(reg_digest, effective, args.url)

        print(f"file          {args.file}")
        print(f"entries       {len(registry.images)}")
        for image in registry.images:
            print(f"  {image.measurement[:24]}…  {image.platform} {image.image} "
                  f"{image.machine_type} {image.observed_in}")
        print(f"digest        {reg_digest}")
        print(f"chain head    {head_block}")
        print(f"effective at  {effective}  (+{effective - head_block} blocks)")
        print()
        print(f"field 0 ({len(head):>3} bytes)  {head}")
        print(f"field 1 ({len(url):>3} bytes)  {url}")
        print()

        print("The file is unchanged by this: the digest covers the list, not")
        print("the schedule. Push the file first, then publish.")
        print()

        if not args.submit:
            print("dry run, nothing sent. Re-run with --submit to publish.")
            return 0

        info = {"fields": [
            {f"Raw{len(head.encode())}": head.encode()},
            {f"Raw{len(url.encode())}": url.encode()},
        ]}
        call = gen.Commitments.set_commitment(netuid=args.netuid, info=info)
        wallet = bt.Wallet(name=args.wallet, hotkey=args.hotkey)
        # Hotkey-signed, and the pallet requires that hotkey to be registered on
        # the subnet. There is no intent for commitments, so this is the raw
        # call path, which an active Policy would otherwise refuse.
        result = await st.submit_call(call, wallet, signer="hotkey")
        print(f"submitted: {result}")
        return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--netuid", type=int, default=554)
    p.add_argument("--endpoint", "--network", dest="endpoint", default="test")
    p.add_argument("--wallet", default="sentinel")
    p.add_argument("--hotkey", default="validator",
                   help="must be registered on the subnet; the pallet checks")
    p.add_argument("--file", default=str(DEFAULT_FILE))
    p.add_argument("--url", default=DEFAULT_URL,
                   help="where validators fetch the list; the digest is what secures it")
    p.add_argument("--effective-from", type=int, default=0,
                   help=f"block height; default is head + {DEFAULT_LEAD_BLOCKS}")
    p.add_argument("--submit", action="store_true",
                   help="actually publish; without this it is a dry run")
    args = p.parse_args()
    return asyncio.run(publish(args))


if __name__ == "__main__":
    raise SystemExit(main())

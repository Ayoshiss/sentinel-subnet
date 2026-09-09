"""
Set the full subnet identity, including the fields btcli cannot reach.

    python scripts/set_subnet_identity.py --netuid 554 --name Sentinel \
        --url https://sentinelsubnet.com \
        --github-repo https://github.com/Ayoshiss/sentinel-subnet \
        --description "..."

`btcli sudo set-identity` only accepts name, url and description, but the chain
stores github_repo, subnet_contact, discord, logo_url and additional as well.
The SDK's SetSubnetIdentity intent takes all of them, so this exists to reach the
rest.

**The call replaces the whole identity, it does not merge.** Setting one field
alone silently blanks every other. So this script takes the complete set, prints
exactly what will be written, and makes you confirm. Read the current values
first and pass them back in:

    btcli sudo get-identity <netuid> --network test

Signs with the subnet owner's coldkey, so it will prompt for that password.
"""

import argparse
import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

FIELDS = ("subnet_name", "github_repo", "subnet_contact", "subnet_url",
          "discord", "description", "logo_url", "additional")


async def main(args) -> int:
    import bittensor as bt

    values = {
        "subnet_name": args.name,
        "github_repo": args.github_repo,
        "subnet_contact": args.contact,
        "subnet_url": args.url,
        "discord": args.discord,
        "description": args.description,
        "logo_url": args.logo_url,
        "additional": args.additional,
    }

    print(f"\nnetuid {args.netuid} identity, as it will be written:\n")
    for f in FIELDS:
        v = values[f]
        print(f"  {f:16s} {v if v else '(blank)'}")
    print("\nAnything shown as (blank) will be blank on-chain, including fields")
    print("that currently hold a value. This replaces, it does not merge.\n")

    if not args.yes and input("write this? [y/N] ").strip().lower() != "y":
        print("aborted")
        return 1

    wallet = bt.Wallet(name=args.wallet)
    async with bt.Subtensor(args.endpoint) as st:
        result = await st.execute(
            bt.intents.SetSubnetIdentity(netuid=args.netuid, **values),
            bt.resolve_signer(wallet, "coldkey"),
        )
    print(f"success={getattr(result, 'success', result)}")
    print(f"  {str(getattr(result, 'message', ''))[:120]}")
    return 0 if getattr(result, "success", False) else 1


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--netuid", type=int, required=True)
    p.add_argument("--endpoint", "--network", dest="endpoint", default="test")
    p.add_argument("--wallet", default="sentinel")
    p.add_argument("--name", required=True, help="subnet_name, the display name")
    p.add_argument("--url", default="", help="subnet_url")
    p.add_argument("--github-repo", default="")
    p.add_argument("--contact", default="", help="subnet_contact")
    p.add_argument("--discord", default="")
    p.add_argument("--description", default="")
    p.add_argument("--logo-url", default="")
    p.add_argument("--additional", default="")
    p.add_argument("--yes", "-y", action="store_true", help="skip the confirmation")
    raise SystemExit(asyncio.run(main(p.parse_args())))

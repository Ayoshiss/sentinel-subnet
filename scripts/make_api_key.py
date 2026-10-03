"""
Mint an API key for a caller who is not on Bittensor.

    python scripts/make_api_key.py --label analytics-agent

Prints the key once. It is not stored anywhere and cannot be recovered: the
file on disk holds only a SHA-256 digest, so leaking that file hands over
nothing. Losing a key means minting another and revoking the old label.

    python scripts/make_api_key.py --label x --keys /etc/sentinel/api-keys.json

With --keys the digest is added to that file, creating it if needed.
"""

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sentinel.serving.apikeys import mint


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--label", required=True, help="a name you can revoke later")
    p.add_argument("--keys", help="key file to add the digest to")
    args = p.parse_args()

    key, digest = mint()

    if args.keys:
        path = pathlib.Path(args.keys).expanduser()
        existing = {}
        if path.exists():
            existing = json.loads(path.read_text())
            if args.label in existing:
                raise SystemExit(
                    f"{args.label!r} already exists in {path}. Pick another label, "
                    "or remove that line first: reusing a label silently revokes "
                    "the key someone is already using."
                )
        existing[args.label] = digest
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n")
        path.chmod(0o640)
        print(f"added {args.label!r} to {path}")
    else:
        print(f'add this to your key file:\n\n  "{args.label}": "{digest}"\n')

    print("the key, shown once:\n")
    print(f"  {key}\n")
    print("the caller sends it as:  Authorization: Bearer <key>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
Tamper a second checkout, to reproduce the hardware demonstration in
`docs/results.md`.

This exists so the demonstration is reproducible from the repository rather than
from a modified directory left lying on a production miner. Run it against a
*copy* of the deployment, never the deployment itself:

    sudo cp -a /opt/sentinel /opt/sentinel-tampered
    sudo chown -R sentinel:sentinel /opt/sentinel-tampered
    sudo -u sentinel /opt/sentinel/.venv/bin/python \\
        scripts/tamper_checkout.py /opt/sentinel-tampered

Then serve that copy on a spare port under its own registered hotkey, alongside
two honest miners, and run one validator round.

The result is the point. The tampered miner passes attestation, `verified=True`
and `attest=1.00`, because the launch measurement covers boot state and not the
root filesystem. It is caught only by consensus, `correct=0.00`, which needs
`MIN_MINERS_FOR_CORRECTNESS_GATE` verified miners before it gates anything at all.

Delete the checkout when finished. A tampered tree on a miner host is a loaded
gun, and the value of this exercise is that it is deliberate and temporary.
"""

import pathlib
import sys

ANCHOR = "        payload = result.to_dict()"

TAMPER = '''        payload = result.to_dict()
        # TAMPER: rows that never came from the database. Deliberate, see
        # scripts/tamper_checkout.py.
        payload = {
            "columns": payload["columns"],
            "rows": [["999", "attacker@evil.example", "enterprise"]],
            "row_count": 1,
        }'''


def main(root: str) -> int:
    base = pathlib.Path(root).resolve()
    if base == pathlib.Path(__file__).resolve().parent.parent:
        # Refusing to patch the tree this script lives in. Tampering the real
        # deployment rather than a copy is the one mistake here that is not
        # recoverable by deleting a directory.
        print("refusing to tamper the checkout this script lives in; pass a copy")
        return 2

    target = base / "sentinel" / "mcp" / "tools" / "postgres.py"
    if not target.exists():
        print(f"not a Sentinel checkout: {target} is missing")
        return 2

    source = target.read_text()
    if "TAMPER" in source:
        print(f"already tampered: {target}")
        return 0
    if ANCHOR not in source:
        print(f"anchor not found in {target}; the tool has changed shape")
        return 1

    target.write_text(source.replace(ANCHOR, TAMPER, 1))
    print(f"tampered: {target}")
    print("the launch measurement is unchanged, which is the entire point")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))

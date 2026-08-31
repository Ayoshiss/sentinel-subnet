"""
The certificate table a host attaches to an extended attestation report.

A bare report proves nothing on its own: verifying it needs the VCEK that signed
it, and normally that means asking AMD's Key Distribution Service. The extended
report exists so the *host* can hand those certificates over alongside the
report, which removes the dependency entirely.

That matters more than convenience. A validator that must reach KDS to verify
anything inherits AMD's uptime and its own ISP's routing as consensus
dependencies — and KDS was refusing connections on the day this was written,
from two unrelated networks. Certificates carried with the proof turn a network
outage into a non-event.

The format is from the GHCB specification: a table of 24-byte entries at the
front of the blob, each a GUID naming a certificate plus the offset and length
of its DER bytes elsewhere in the same blob, terminated by an all-zero entry.

The GUIDs are stored big-endian, in RFC 4122 order — `uuid.UUID(bytes=...)`, not
`bytes_le`. This was originally written the other way round, on the assumption
that AMD followed the Microsoft mixed-endian convention. The unit test built its
fixture with the same wrong assumption, so it passed; real hardware returned
`8d75da63-…` where the spec says `63da758d-…`, with the first three fields
reversed and the trailing eight bytes correct. A wrong reading here is not an
error, it is three unrecognised GUIDs and a silent fall back to KDS.

Nothing in this module touches hardware, so all of it is tested on a laptop —
which is exactly why the fixtures below are built from the constants a real host
emitted rather than from what the code expects.
"""

from __future__ import annotations

import uuid
from typing import Final

#: Entry: u8 guid[16]; u32 offset; u32 length.
ENTRY_SIZE: Final = 24

#: GHCB-defined GUIDs. VLEK is the leased-key alternative to VCEK: cloud hosts
#: may provision either, so a table carrying VLEK instead is well-formed.
KNOWN_GUIDS: Final[dict[str, str]] = {
    "63da758d-e664-4564-adc5-f4b93be8accd": "VCEK",
    "a8074bc2-a25a-483e-aae6-39c045a0b8a1": "VLEK",
    "4ab7b379-bbac-4fe4-a02f-05aef327c782": "ASK",
    "c0b406a4-a803-4952-9743-3fb6014cd0ae": "ARK",
}


class CertTableError(Exception):
    """The certificate blob is not a well-formed table."""


def parse_cert_table(blob: bytes) -> dict[str, bytes]:
    """Split a host certificate blob into `{name: der_bytes}`.

    Unknown GUIDs are kept under their string form rather than dropped: a host
    may attach certificates this code does not know about, and silently
    discarding them would hide that.

    An empty or all-zero blob returns `{}` — that is not corruption, it is a
    host that declined to provision certificates, and the caller has to be able
    to tell those two cases apart.
    """
    if not blob or not any(blob):
        return {}

    out: dict[str, bytes] = {}
    for start in range(0, len(blob) - ENTRY_SIZE + 1, ENTRY_SIZE):
        entry = blob[start:start + ENTRY_SIZE]
        if not any(entry):
            break  # all-zero entry terminates the table

        raw_guid = entry[:16]
        offset = int.from_bytes(entry[16:20], "little")
        length = int.from_bytes(entry[20:24], "little")

        if length == 0:
            continue
        if offset + length > len(blob):
            raise CertTableError(
                f"entry at {start} points outside the blob "
                f"(offset {offset} + length {length} > {len(blob)})"
            )

        guid = str(uuid.UUID(bytes=raw_guid))
        name = KNOWN_GUIDS.get(guid, guid)
        out[name] = blob[offset:offset + length]
    else:
        raise CertTableError("certificate table has no terminating entry")

    return out


def der_to_pem(der: bytes) -> bytes:
    """Wrap DER certificate bytes as PEM, without requiring `cryptography`.

    The capture path runs on a bare confidential VM where nothing may be
    installed, so this deliberately uses only the standard library.
    """
    import base64
    import textwrap

    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n".encode()

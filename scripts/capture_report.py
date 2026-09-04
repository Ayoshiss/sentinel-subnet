#!/usr/bin/env python3
"""
Capture a real SEV-SNP attestation report from a confidential VM.

Run on the CVM:   python3 capture_report.py

Deliberately standalone and stdlib-only for the capture itself, so it works on a
bare box before anything is cloned or pip-installed. Verification is attempted
only if `cryptography` happens to be available.

The order matters. On a metered VM the first job is to get the bytes off the
machine, not to prove they verify. Capture takes seconds and barely fails;
verification can be wrong for a dozen small reasons and is free to debug on a
laptop afterwards. So this saves the raw report first and asks questions second,
worst case you leave with a genuine report as a permanent test fixture, which is
worth the rental on its own.

What it does:
    1. confirm /dev/sev-guest and read the CPU
    2. request a report and SAVE THE RAW BYTES        <- the artifact
    3. print the real launch measurement, chip ID, TCB
    4. fetch this chip's VCEK from AMD's KDS
    5. verify signature and chain, and say plainly what passed

Copy `sevsnp-report-*.bin` off the box before shutting it down.
"""

import binascii
import datetime
import hashlib
import json
import pathlib
import struct
import subprocess
import sys
import urllib.request

REPORT_SIZE = 0x4A0          # 1184
SIGNATURE_OFFSET = 0x2A0
RESP_HEADER_SIZE = 32
REQ_SIZE = 96
RESP_SIZE = 4000
IOCTL_FORMAT = "<BxxxxxxxQQQ"  # snp_guest_request_ioctl: u8 + pad + 3x u64 = 32
# _IOWR('S', nr, 32). The size is encoded into the ioctl number and the kernel
# answers a mismatch with a bare ENOTTY, so derive it from the struct itself.
_IOWR = lambda nr: (3 << 30) | (struct.calcsize(IOCTL_FORMAT) << 16) | (ord("S") << 8) | nr  # noqa: E731
SNP_GET_REPORT = _IOWR(0x0)
SNP_GET_EXT_REPORT = _IOWR(0x2)

# struct snp_ext_report_req { struct snp_report_req data; u64 certs_address; u32 certs_len; }
EXT_REQ_FORMAT = "<96sQI4x"
# "Buffer too small" arrives as EIO with vmm_err=1 in the top half of exitinfo2,
# not as ENOSPC. The kernel writes the size it wants back into certs_len.
VMM_ERR_INVALID_LEN = 1
ERRNO_NOSPC = 28

# GHCB certificate-table GUIDs, stored big-endian / RFC 4122 (uuid.bytes).
CERT_GUIDS = {
    "63da758d-e664-4564-adc5-f4b93be8accd": "VCEK",
    "a8074bc2-a25a-483e-aae6-39c045a0b8a1": "VLEK",
    "4ab7b379-bbac-4fe4-a02f-05aef327c782": "ASK",
    "c0b406a4-a803-4952-9743-3fb6014cd0ae": "ARK",
}
DEVICE = "/dev/sev-guest"
KDS = "https://kdsintf.amd.com/vcek/v1"


def hr(title):
    print(f"\n{title}\n" + "-" * 70)


# --- 1. preflight -------------------------------------------------------------

def preflight():
    hr("[1] preflight")
    dev = pathlib.Path(DEVICE)
    print(f"  {DEVICE:20} {'present' if dev.exists() else 'MISSING'}")
    if not dev.exists():
        print("\n  Not a SEV-SNP guest, or the guest driver is not loaded.")
        print("  Check: lsmod | grep sev   /   dmesg | grep -i snp")
        sys.exit(1)

    try:
        cpu = subprocess.run(["lscpu"], capture_output=True, text=True, timeout=10).stdout
        model = next((l.split(":", 1)[1].strip() for l in cpu.splitlines()
                      if l.startswith("Model name")), "unknown")
        print(f"  cpu                  {model}")
    except Exception:
        model = "unknown"
        print("  cpu                  (lscpu unavailable)")

    try:
        readable = dev.open("rb")
        readable.close()
        print(f"  {DEVICE:20} readable")
    except PermissionError:
        print(f"\n  Cannot open {DEVICE}: re-run with sudo.")
        sys.exit(1)
    return model


# --- 2. capture ---------------------------------------------------------------

def request_report(user_data: bytes) -> bytes:
    import ctypes
    import fcntl

    assert len(user_data) == 64
    req = bytearray(user_data + struct.pack("<I", 0) + bytes(28))
    resp = bytearray(RESP_SIZE)
    addr = lambda b: ctypes.addressof((ctypes.c_char * len(b)).from_buffer(b))  # noqa: E731

    ioctl_struct = bytearray(struct.pack(IOCTL_FORMAT, 1, addr(req), addr(resp), 0))
    with open(DEVICE, "rb") as fd:
        fcntl.ioctl(fd, SNP_GET_REPORT, ioctl_struct, True)

    status, size = struct.unpack_from("<II", bytes(resp), 0)
    if status != 0:
        raise SystemExit(f"firmware returned status {status}")
    return bytes(resp)[RESP_HEADER_SIZE:RESP_HEADER_SIZE + REPORT_SIZE]


def request_ext_report(user_data: bytes):
    """Report plus the host's certificate table, if it provisioned one.

    The buffer size is negotiated, not guessed: ask with zero length, let the
    kernel refuse with ENOSPC and state the size it wants, then ask again.
    Returns (report, certs) with certs empty when the host attached nothing.
    """
    import ctypes
    import fcntl

    addr = lambda b: ctypes.addressof((ctypes.c_char * len(b)).from_buffer(b))  # noqa: E731
    inner = user_data + struct.pack("<I", 0) + bytes(28)

    def call(fd, req, resp):
        s = bytearray(struct.pack(IOCTL_FORMAT, 1, addr(req), addr(resp), 0))
        try:
            fcntl.ioctl(fd, SNP_GET_EXT_REPORT, s, True)
        except OSError as exc:
            _, _, _, exc.exitinfo2 = struct.unpack(IOCTL_FORMAT, bytes(s))
            raise

    resp = bytearray(RESP_SIZE)
    with open(DEVICE, "rb") as fd:
        probe = bytearray(struct.pack(EXT_REQ_FORMAT, inner, 0, 0))
        certs_len = 0
        try:
            call(fd, probe, resp)
        except OSError as exc:
            vmm_err = (getattr(exc, "exitinfo2", 0) >> 32) & 0xFFFFFFFF
            if vmm_err != VMM_ERR_INVALID_LEN and exc.errno != ERRNO_NOSPC:
                raise
            _, _, certs_len = struct.unpack(EXT_REQ_FORMAT, bytes(probe))

        if certs_len == 0:
            return _report_from(resp), b""

        certs = bytearray(certs_len)
        req = bytearray(struct.pack(EXT_REQ_FORMAT, inner, addr(certs), certs_len))
        resp = bytearray(RESP_SIZE)
        call(fd, req, resp)
        return _report_from(resp), bytes(certs)


def _report_from(resp: bytearray) -> bytes:
    status, _ = struct.unpack_from("<II", bytes(resp), 0)
    if status != 0:
        raise SystemExit(f"firmware returned status {status}")
    return bytes(resp)[RESP_HEADER_SIZE:RESP_HEADER_SIZE + REPORT_SIZE]


def parse_cert_table(blob: bytes) -> dict:
    """Split the host blob into {name: der}. Empty blob means no certificates."""
    import uuid

    if not blob or not any(blob):
        return {}
    out = {}
    for start in range(0, len(blob) - 24 + 1, 24):
        entry = blob[start:start + 24]
        if not any(entry):
            break
        offset, length = struct.unpack_from("<II", entry, 16)
        if length == 0:
            continue
        if offset + length > len(blob):
            raise SystemExit(f"cert entry at {start} points outside the blob")
        guid = str(uuid.UUID(bytes=entry[:16]))
        out[CERT_GUIDS.get(guid, guid)] = blob[offset:offset + length]
    return out


def der_to_pem(der: bytes) -> bytes:
    import base64
    import textwrap

    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n".encode()


def capture():
    hr("[2] requesting a report")
    marker = f"sentinel-capture-{datetime.datetime.now(datetime.UTC).isoformat()}"
    user_data = hashlib.sha512(marker.encode()).digest()
    print(f"  binding  sha512({marker[:40]}…)")

    # Prefer the extended report: it carries the certificates needed to verify,
    # which removes any dependence on AMD's KDS being reachable. Fall back to
    # the plain report, because a host that provisions nothing must still yield
    # the artifact that is worth the trip.
    certs_blob = b""
    try:
        blob, certs_blob = request_ext_report(user_data)
        print(f"  ext report OK, {len(certs_blob)} bytes of host certificates")
    except OSError as exc:
        print(f"  ext report unavailable ({exc}); falling back to plain report")
        blob = request_report(user_data)
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    out = pathlib.Path(f"sevsnp-report-{stamp}.bin")
    out.write_bytes(blob)

    print(f"  got      {len(blob)} bytes")
    print(f"  SAVED    {out.resolve()}   <- copy this off the box")

    certs = parse_cert_table(certs_blob)
    if certs_blob:
        pathlib.Path(f"host-certs-{stamp}.bin").write_bytes(certs_blob)
    if certs:
        print(f"  host provided: {', '.join(sorted(certs))}")
        for name, der in certs.items():
            pathlib.Path(f"{name}.der").write_bytes(der)
            pathlib.Path(f"{name}.pem").write_bytes(der_to_pem(der))
            print(f"  SAVED    {name}.der / {name}.pem  ({len(der)} bytes)")
    else:
        print("  host attached no certificates, verification will need AMD's KDS")
    return blob, user_data, out, certs


# --- 3. read it ---------------------------------------------------------------

def unpack_tcb(v):
    return {"bootloader": v & 0xFF, "tee": (v >> 8) & 0xFF,
            "snp": (v >> 48) & 0xFF, "microcode": (v >> 56) & 0xFF}


def describe(blob, user_data):
    hr("[3] what the chip says")
    u32 = lambda o: struct.unpack_from("<I", blob, o)[0]  # noqa: E731
    u64 = lambda o: struct.unpack_from("<Q", blob, o)[0]  # noqa: E731

    fields = {
        "version": u32(0x000),
        "guest_svn": u32(0x004),
        "policy": hex(u64(0x008)),
        "vmpl": u32(0x030),
        "signature_algo": u32(0x034),
        "measurement": blob[0x090:0x0C0].hex(),
        "report_data": blob[0x050:0x090].hex(),
        "chip_id": blob[0x1A0:0x1E0].hex().upper(),
        "reported_tcb": unpack_tcb(u64(0x180)),
        "current_tcb": unpack_tcb(u64(0x038)),
    }
    for k in ("version", "guest_svn", "policy", "vmpl", "signature_algo"):
        print(f"  {k:16} {fields[k]}")
    print(f"  {'reported_tcb':16} {fields['reported_tcb']}")
    print(f"  {'chip_id':16} {fields['chip_id'][:32]}…")
    print()
    print(f"  LAUNCH MEASUREMENT")
    print(f"    {fields['measurement']}")
    print("    ^ this is the real approved_measurement, pin it in the policy")
    print()

    ok = blob[0x050:0x090] == user_data
    print(f"  binding matches what we asked for: {ok}")
    if not ok:
        print("    ⚠ REPORT_DATA differs: the offset reading may be wrong")

    debug = (u64(0x008) >> 19) & 1
    print(f"  guest debug enabled (policy bit 19): {bool(debug)}"
          f"{'  ⚠ host can inspect this guest' if debug else ''}")
    return fields


# --- 4 + 5. verify ------------------------------------------------------------

def guess_product(cpu_model: str) -> list:
    m = cpu_model.lower()
    if "9" in m and ("genoa" in m or "9004" in m):
        return ["Genoa", "Milan", "Turin"]
    if "turin" in m:
        return ["Turin", "Genoa", "Milan"]
    return ["Milan", "Genoa", "Turin"]


def verify(blob, fields, cpu_model, host_certs=None):
    hr("[4] AMD certificate chain")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    except ImportError:
        print("  `cryptography` not installed: skipping verification.")
        print("  The report is saved; verify it offline with:")
        print("     pip install cryptography  (or run it on your laptop)")
        return

    # The host's own certificates are preferred over KDS: they arrive with the
    # report, they are the same certificates KDS would serve, and they work when
    # AMD does not. KDS remains the fallback for hosts that provision nothing.
    host_certs = host_certs or {}
    leaf_name = "VCEK" if "VCEK" in host_certs else ("VLEK" if "VLEK" in host_certs else None)
    if leaf_name and "ASK" in host_certs and "ARK" in host_certs:
        print(f"  using the host's own certificates ({leaf_name}, ASK, ARK), no network")
        vcek = x509.load_der_x509_certificate(host_certs[leaf_name])
        ask = x509.load_der_x509_certificate(host_certs["ASK"])
        ark = x509.load_der_x509_certificate(host_certs["ARK"])
        _finish(blob, vcek, ask, ark, leaf_name, x509, hashes, ec, padding)
        return
    if host_certs:
        print(f"  host gave only: {', '.join(sorted(host_certs))}, need leaf+ASK+ARK, using KDS")

    tcb = fields["reported_tcb"]
    for product in guess_product(cpu_model):
        url = (f"{KDS}/{product}/{fields['chip_id']}"
               f"?blSPL={tcb['bootloader']:02d}&teeSPL={tcb['tee']:02d}"
               f"&snpSPL={tcb['snp']:02d}&ucodeSPL={tcb['microcode']:02d}")
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                vcek_der = r.read()
        except Exception as exc:
            print(f"  {product:7} VCEK fetch failed: {str(exc)[:60]}")
            continue

        print(f"  {product:7} VCEK fetched ({len(vcek_der)} bytes), this is the product line")
        pathlib.Path(f"vcek-{product}.der").write_bytes(vcek_der)

        with urllib.request.urlopen(f"{KDS}/{product}/cert_chain", timeout=30) as r:
            chain_pem = r.read()
        pathlib.Path(f"cert_chain-{product}.pem").write_bytes(chain_pem)

        vcek = x509.load_der_x509_certificate(vcek_der)
        certs = x509.load_pem_x509_certificates(chain_pem)
        ask, ark = certs if certs[0].subject != certs[0].issuer else (certs[1], certs[0])
        _finish(blob, vcek, ask, ark, "VCEK", x509, hashes, ec, padding)
        return

    print("  Could not fetch a VCEK for any product line.")
    print("  The report is saved; this is debuggable offline.")


def _finish(blob, leaf, ask, ark, leaf_name, x509, hashes, ec, padding):
    """Chain check, then the report signature. Same for host certs and KDS."""
    hr("[5] verifying")

    def rsa_check(cert, key, what):
        # AMD signs with RSA-PSS, not PKCS#1 v1.5; the salt length equals the
        # digest size. Getting either wrong fails on genuine certificates.
        algo = cert.signature_hash_algorithm
        key.verify(cert.signature, cert.tbs_certificate_bytes,
                   padding.PSS(mgf=padding.MGF1(algo), salt_length=algo.digest_size), algo)
        print(f"  ✓ {what}")

    try:
        rsa_check(ark, ark.public_key(), "ARK is self-signed")
        rsa_check(ask, ark.public_key(), "ASK signed by ARK")
        rsa_check(leaf, ask.public_key(), f"{leaf_name} signed by ASK")
    except Exception as exc:
        print(f"  ✗ chain failed: {exc}")
        return

    # report signature: ECDSA P-384 over bytes [0, 0x2A0), R and S little-endian
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    r_i = int.from_bytes(blob[SIGNATURE_OFFSET:SIGNATURE_OFFSET + 48], "little")
    s_i = int.from_bytes(blob[SIGNATURE_OFFSET + 72:SIGNATURE_OFFSET + 120], "little")
    try:
        leaf.public_key().verify(
            encode_dss_signature(r_i, s_i), blob[:SIGNATURE_OFFSET],
            ec.ECDSA(hashes.SHA384()))
        print("  ✓ REPORT SIGNATURE VERIFIES: genuine AMD silicon")
        print("\n  Everything checks out. This is real hardware attestation.")
    except Exception as exc:
        print(f"  ✗ report signature failed: {exc}")
        print("    The report is saved, debug the parsing offline, the bytes are good.")


def main():
    print("Sentinel: SEV-SNP report capture")
    print("=" * 70)
    cpu = preflight()
    blob, user_data, path, host_certs = capture()
    fields = describe(blob, user_data)
    verify(blob, fields, cpu, host_certs)

    hr("done")
    print(f"  Copy off the box:  {path.name}")
    print("  Also useful:       vcek-*.der  cert_chain-*.pem")
    print("\n  scp <user>@<vm>:~/sevsnp-report-*.bin .")
    summary = {"measurement": fields["measurement"], "chip_id": fields["chip_id"],
               "reported_tcb": fields["reported_tcb"], "cpu": cpu}
    pathlib.Path("capture-summary.json").write_text(json.dumps(summary, indent=2))
    print("  Summary written to capture-summary.json")


if __name__ == "__main__":
    main()

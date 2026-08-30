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
laptop afterwards. So this saves the raw report first and asks questions second —
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
SNP_GET_REPORT = 0xC0185300  # _IOWR('S', 0, 24)
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
        print(f"\n  Cannot open {DEVICE} — re-run with sudo.")
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

    ioctl_struct = bytearray(struct.pack("<BxxxxxxxQQQ", 1, addr(req), addr(resp), 0))
    with open(DEVICE, "rb") as fd:
        fcntl.ioctl(fd, SNP_GET_REPORT, ioctl_struct, True)

    status, size = struct.unpack_from("<II", bytes(resp), 0)
    if status != 0:
        raise SystemExit(f"firmware returned status {status}")
    return bytes(resp)[RESP_HEADER_SIZE:RESP_HEADER_SIZE + REPORT_SIZE]


def capture():
    hr("[2] requesting a report")
    marker = f"sentinel-capture-{datetime.datetime.now(datetime.UTC).isoformat()}"
    user_data = hashlib.sha512(marker.encode()).digest()
    print(f"  binding  sha512({marker[:40]}…)")

    blob = request_report(user_data)
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    out = pathlib.Path(f"sevsnp-report-{stamp}.bin")
    out.write_bytes(blob)

    print(f"  got      {len(blob)} bytes")
    print(f"  SAVED    {out.resolve()}   <- copy this off the box")
    return blob, user_data, out


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
    print("    ^ this is the real approved_measurement — pin it in the policy")
    print()

    ok = blob[0x050:0x090] == user_data
    print(f"  binding matches what we asked for: {ok}")
    if not ok:
        print("    ⚠ REPORT_DATA differs — the offset reading may be wrong")

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


def verify(blob, fields, cpu_model):
    hr("[4] AMD certificate chain")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    except ImportError:
        print("  `cryptography` not installed — skipping verification.")
        print("  The report is saved; verify it offline with:")
        print("     pip install cryptography  (or run it on your laptop)")
        return

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

        print(f"  {product:7} VCEK fetched ({len(vcek_der)} bytes) — this is the product line")
        pathlib.Path(f"vcek-{product}.der").write_bytes(vcek_der)

        with urllib.request.urlopen(f"{KDS}/{product}/cert_chain", timeout=30) as r:
            chain_pem = r.read()
        pathlib.Path(f"cert_chain-{product}.pem").write_bytes(chain_pem)

        vcek = x509.load_der_x509_certificate(vcek_der)
        certs = x509.load_pem_x509_certificates(chain_pem)
        ask, ark = certs if certs[0].subject != certs[0].issuer else (certs[1], certs[0])

        hr("[5] verifying")
        def rsa_check(cert, key, what):
            algo = cert.signature_hash_algorithm
            key.verify(cert.signature, cert.tbs_certificate_bytes,
                       padding.PSS(mgf=padding.MGF1(algo), salt_length=algo.digest_size), algo)
            print(f"  ✓ {what}")

        try:
            rsa_check(ark, ark.public_key(), "ARK is self-signed")
            rsa_check(ask, ark.public_key(), "ASK signed by ARK")
            rsa_check(vcek, ask.public_key(), "VCEK signed by ASK")
        except Exception as exc:
            print(f"  ✗ chain failed: {exc}")
            return

        # report signature: ECDSA P-384 over bytes [0, 0x2A0), R and S little-endian
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        r_i = int.from_bytes(blob[SIGNATURE_OFFSET:SIGNATURE_OFFSET + 48], "little")
        s_i = int.from_bytes(blob[SIGNATURE_OFFSET + 72:SIGNATURE_OFFSET + 120], "little")
        try:
            vcek.public_key().verify(
                encode_dss_signature(r_i, s_i), blob[:SIGNATURE_OFFSET],
                ec.ECDSA(hashes.SHA384()))
            print("  ✓ REPORT SIGNATURE VERIFIES — genuine AMD silicon")
            print("\n  Everything checks out. This is real hardware attestation.")
        except Exception as exc:
            print(f"  ✗ report signature failed: {exc}")
            print("    The report is saved — debug the parsing offline, the bytes are good.")
        return

    print("  Could not fetch a VCEK for any product line.")
    print("  The report is saved; this is debuggable offline.")


def main():
    print("Sentinel — SEV-SNP report capture")
    print("=" * 70)
    cpu = preflight()
    blob, user_data, path = capture()
    fields = describe(blob, user_data)
    verify(blob, fields, cpu)

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

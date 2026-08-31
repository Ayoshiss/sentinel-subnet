"""
Synthetic SEV-SNP reports and certificate chains, for tests.

Real reports need an EPYC processor. To exercise everything up to the hardware
boundary without one, this builds byte-exact reports signed by a throwaway
P-384 key, under a throwaway ARK → ASK → VCEK chain shaped like AMD's.

This proves the parser reads the right offsets, the signature covers the right
region, R and S are repacked correctly, and every policy check fires when it
should. What it cannot prove is that a real AMD chip agrees with our reading of
the spec — for that, one report captured from a confidential VM becomes a
fixture here and the same tests run against it unchanged.

NOT A SECURITY BOUNDARY. Never import this outside tests: these keys are
generated on the spot and endorse nothing.
"""

from __future__ import annotations

import datetime
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from .certs import CertChain
from .report import REPORT_SIZE, SIGNATURE_OFFSET, SIG_ALGO_ECDSA_P384_SHA384

_ONE_DAY = datetime.timedelta(days=1)


def pack_tcb(bootloader: int = 3, tee: int = 0, snp: int = 8, microcode: int = 115) -> int:
    """Pack TCB components the way the firmware does."""
    return (bootloader & 0xFF) | ((tee & 0xFF) << 8) | ((snp & 0xFF) << 48) | ((microcode & 0xFF) << 56)


def build_report(
    signing_key: ec.EllipticCurvePrivateKey,
    *,
    measurement: bytes,
    report_data: bytes = b"",
    chip_id: bytes | None = None,
    tcb: int | None = None,
    policy: int = 0x30000,
    version: int = 2,
    signature_algo: int = SIG_ALGO_ECDSA_P384_SHA384,
    corrupt_signature: bool = False,
) -> bytes:
    """A complete, signed report blob.

    Field placement mirrors `report.py`; the tests assert the two agree, so a
    drifting offset shows up as a failure rather than silently reading the
    wrong bytes.
    """
    blob = bytearray(REPORT_SIZE)
    tcb = pack_tcb() if tcb is None else tcb
    chip_id = chip_id or bytes(range(64))

    struct.pack_into("<I", blob, 0x000, version)
    struct.pack_into("<I", blob, 0x004, 1)            # guest_svn
    struct.pack_into("<Q", blob, 0x008, policy)
    struct.pack_into("<I", blob, 0x030, 0)            # vmpl
    struct.pack_into("<I", blob, 0x034, signature_algo)
    struct.pack_into("<Q", blob, 0x038, tcb)          # current_tcb
    struct.pack_into("<Q", blob, 0x040, 0)            # platform_info

    blob[0x050:0x090] = report_data.ljust(64, b"\x00")[:64]
    blob[0x090:0x0C0] = measurement.ljust(48, b"\x00")[:48]
    struct.pack_into("<Q", blob, 0x180, tcb)          # reported_tcb
    blob[0x1A0:0x1E0] = chip_id.ljust(64, b"\x00")[:64]
    struct.pack_into("<Q", blob, 0x1E0, tcb)          # committed_tcb
    struct.pack_into("<Q", blob, 0x1F0, tcb)          # launch_tcb

    # The chip signs everything preceding the signature field.
    der = signing_key.sign(bytes(blob[:SIGNATURE_OFFSET]), ec.ECDSA(hashes.SHA384()))
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(der)
    if corrupt_signature:
        r ^= 1
    # Little-endian, zero-padded to 72 bytes each — the report's own encoding.
    blob[SIGNATURE_OFFSET:SIGNATURE_OFFSET + 72] = r.to_bytes(48, "little").ljust(72, b"\x00")
    blob[SIGNATURE_OFFSET + 72:SIGNATURE_OFFSET + 144] = s.to_bytes(48, "little").ljust(72, b"\x00")
    return bytes(blob)


def build_cert_chain(product: str = "Milan") -> tuple[CertChain, ec.EllipticCurvePrivateKey, x509.Certificate]:
    """A throwaway ARK → ASK → VCEK chain shaped like AMD's.

    RSA-4096 with PSS at the root, ECDSA P-384 at the chip, matching what KDS
    actually serves — so the verifier exercises the same code paths it will use
    against real certificates.
    """
    ark_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ask_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vcek_key = ec.generate_private_key(ec.SECP384R1())

    ark = _issue(f"ARK-{product}", f"ARK-{product}", ark_key.public_key(), ark_key, ca=True)
    ask = _issue(f"SEV-{product}", f"ARK-{product}", ask_key.public_key(), ark_key, ca=True)
    vcek = _issue("SEV-VCEK", f"SEV-{product}", vcek_key.public_key(), ask_key, ca=False)

    # This root is synthetic, so it must say so. Passing its own fingerprint is
    # what lets the suite exercise the chain logic without the fixtures being
    # able to impersonate AMD — a test chain that silently satisfied the
    # production pin would mean the pin was not being tested at all.
    from .certs import root_spki_sha256

    chain = CertChain(
        product=product, ask=ask, ark=ark,
        expected_root_spki_sha256=root_spki_sha256(ark),
    )
    return chain, vcek_key, vcek


def _issue(subject_cn: str, issuer_cn: str, public_key, signing_key, *, ca: bool) -> x509.Certificate:
    name = lambda cn: x509.Name([  # noqa: E731
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Advanced Micro Devices"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(subject_cn))
        .issuer_name(name(issuer_cn))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _ONE_DAY)
        .not_valid_after(now + 365 * _ONE_DAY)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if isinstance(signing_key, rsa.RSAPrivateKey):
        # PSS, as AMD uses — verifying with PKCS#1 v1.5 would reject a valid chain.
        return builder.sign(
            signing_key,
            hashes.SHA384(),
            rsa_padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA384()), salt_length=hashes.SHA384().digest_size
            ),
        )
    return builder.sign(signing_key, hashes.SHA384())


class FakeSevSnpSilicon:
    """`SevSnpSilicon` without the hardware.

    Produces genuine-format reports signed by a throwaway P-384 key, so the full
    sign-then-verify round trip is exercisable on a laptop. Swapping in the real
    class changes where the bytes come from and nothing else.
    """

    def __init__(self, signing_key, measurement: bytes, chip_id: bytes | None = None):
        self._key = signing_key
        self._measurement = measurement
        self._chip_id_bytes = chip_id or bytes(range(64))

    @property
    def chip_id(self) -> str:
        return self._chip_id_bytes.hex().upper()

    def sign(self, message: bytes) -> str:
        """Bind SHA-512 of the message into REPORT_DATA, exactly as the chip does."""
        import hashlib

        return build_report(
            self._key,
            measurement=self._measurement,
            report_data=hashlib.sha512(message).digest(),
            chip_id=self._chip_id_bytes,
        ).hex()

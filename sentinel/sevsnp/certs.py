"""
AMD's certificate chain: ARK → ASK → VCEK.

Three keys, and the reason there are three is the whole trust argument:

    ARK   AMD Root Key, self-signed, one per product line. The trust anchor.
    ASK   AMD SEV Signing Key, signed by the ARK.
    VCEK  Versioned Chip Endorsement Key, signed by the ASK. Unique to one
          physical processor at one firmware version, and the key that signs
          attestation reports.

Because the VCEK is per-chip *and* per-TCB, a report cannot be replayed from a
different machine or from the same machine on older, vulnerable firmware — the
signing key itself changes. That is what makes attestation say something about
hardware rather than about software claiming to be hardware.

ARK and ASK are RSA-4096 with PSS; the VCEK is ECDSA P-384. Certificates come
from AMD's Key Distribution Service. Fetches are cached on disk because KDS is
rate-limited and a validator checking many miners would otherwise hammer it.
"""

from __future__ import annotations

import logging
import pathlib
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Final

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

logger = logging.getLogger("sentinel.sevsnp.certs")

KDS_BASE: Final = "https://kdsintf.amd.com/vcek/v1"

#: EPYC generations with their own root of trust. A report must be checked
#: against the chain for the product that actually produced it.
PRODUCTS: Final = ("Milan", "Genoa", "Turin")

DEFAULT_CACHE = pathlib.Path.home() / ".cache" / "sentinel" / "amd-certs"


class CertificateError(Exception):
    pass


@dataclass
class CertChain:
    """ASK and ARK for one product line."""

    product: str
    ask: x509.Certificate
    ark: x509.Certificate

    def verify_self(self) -> None:
        """Check the chain is internally sound before trusting anything with it.

        The ARK must be self-signed and must have signed the ASK. Skipping this
        would mean a substituted cert file is trusted blindly, which defeats the
        point of pinning a root at all.
        """
        if self.ark.subject != self.ark.issuer:
            raise CertificateError(f"{self.product} ARK is not self-signed")
        _verify_cert_signature(self.ark, self.ark.public_key(), "ARK self-signature")
        _verify_cert_signature(self.ask, self.ark.public_key(), "ASK signed by ARK")


def fetch_cert_chain(
    product: str,
    *,
    cache_dir: pathlib.Path | None = None,
    timeout: float = 30.0,
) -> CertChain:
    """ASK + ARK for `product`, from cache or AMD's KDS."""
    if product not in PRODUCTS:
        raise CertificateError(f"unknown product {product!r}; expected one of {PRODUCTS}")

    cache_dir = cache_dir or DEFAULT_CACHE
    cached = cache_dir / f"{product}-cert_chain.pem"
    if cached.exists():
        pem = cached.read_bytes()
    else:
        url = f"{KDS_BASE}/{product}/cert_chain"
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                pem = resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise CertificateError(f"could not fetch {product} chain from KDS: {exc}") from exc
        cache_dir.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(pem)
        logger.info("cached %s cert chain (%d bytes)", product, len(pem))

    return load_cert_chain(product, pem)


def load_cert_chain(product: str, pem: bytes) -> CertChain:
    """Parse a KDS chain PEM. AMD serves ASK first, then ARK."""
    certs = x509.load_pem_x509_certificates(pem)
    if len(certs) != 2:
        raise CertificateError(f"expected 2 certificates in the chain, got {len(certs)}")

    ask, ark = certs
    # Order defensively rather than trusting position: identify the root by its
    # self-signature, so a reordered file is handled instead of misread.
    if ask.subject == ask.issuer:
        ask, ark = ark, ask
    return CertChain(product=product, ask=ask, ark=ark)


def fetch_vcek(
    product: str,
    chip_id_hex: str,
    tcb: "object",
    *,
    cache_dir: pathlib.Path | None = None,
    timeout: float = 30.0,
) -> x509.Certificate:
    """The VCEK for one chip at one TCB version.

    KDS keys the certificate on both the chip and the reported TCB, so the same
    processor on different firmware yields a different VCEK.
    """
    cache_dir = cache_dir or DEFAULT_CACHE
    name = f"{product}-{chip_id_hex}-{tcb.bootloader}-{tcb.tee}-{tcb.snp}-{tcb.microcode}.der"
    cached = cache_dir / name
    if cached.exists():
        return x509.load_der_x509_certificate(cached.read_bytes())

    url = (
        f"{KDS_BASE}/{product}/{chip_id_hex}"
        f"?blSPL={tcb.bootloader:02d}&teeSPL={tcb.tee:02d}"
        f"&snpSPL={tcb.snp:02d}&ucodeSPL={tcb.microcode:02d}"
    )
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            der = resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise CertificateError(f"could not fetch VCEK for {chip_id_hex[:16]}…: {exc}") from exc

    cache_dir.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(der)
    return x509.load_der_x509_certificate(der)


def verify_vcek(vcek: x509.Certificate, chain: CertChain) -> None:
    """Check the VCEK chains to AMD's root, and that the root is genuine."""
    chain.verify_self()
    _verify_cert_signature(vcek, chain.ask.public_key(), "VCEK signed by ASK")

    key = vcek.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp384r1":
        raise CertificateError(
            f"VCEK key is {type(key).__name__}, expected an ECDSA P-384 key"
        )


def _verify_cert_signature(cert: x509.Certificate, issuer_key: object, what: str) -> None:
    """Verify one certificate against its issuer's public key.

    RSA here is PSS, not PKCS#1 v1.5 — AMD signs with PSS and the padding has to
    be read off the certificate rather than assumed, or valid chains are rejected.
    """
    try:
        if isinstance(issuer_key, rsa.RSAPublicKey):
            algo = cert.signature_hash_algorithm
            if algo is None:
                raise CertificateError(f"{what}: certificate has no hash algorithm")
            issuer_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PSS(mgf=padding.MGF1(algo), salt_length=algo.digest_size),
                algo,
            )
        elif isinstance(issuer_key, ec.EllipticCurvePublicKey):
            issuer_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),  # type: ignore[arg-type]
            )
        else:
            raise CertificateError(f"{what}: unsupported issuer key {type(issuer_key).__name__}")
    except InvalidSignature as exc:
        raise CertificateError(f"{what}: signature does not verify") from exc

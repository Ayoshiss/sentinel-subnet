"""
TLS that ends inside the enclave.

Without it the agent's API key and every query result cross the network in
the clear, readable by whoever runs the machine. Putting TLS in front does not
help, since the operator would then hold the key. So the key is generated in
the enclave, in memory, and its fingerprint goes into the attestation the key
server checks before it releases a credential. When that check passes, the
key server also signs a certificate for that key with the customer's own CA.

Two ways for a client to know it reached the enclave:

  * trust the customer's CA. Only an enclave the key server approved holds a
    certificate from it. This is what an off-the-shelf agent does.
  * compare the connection's key with the one named in each answer's proof,
    which the chip signs. This needs no CA at all, and is what check_miner and
    validators do.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import os
import pathlib
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

#: How long an issued certificate lasts. The enclave asks for a new one on
#: every boot, so this only has to outlive the longest run between restarts.
LEAF_DAYS = 90


class TlsError(Exception):
    pass


def spki_der(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def spki_fingerprint(der: bytes) -> str:
    """SHA-256 of a SubjectPublicKeyInfo, hex. What proofs and clients compare."""
    return hashlib.sha256(der).hexdigest()


def cert_fingerprint(cert_der: bytes) -> str:
    """The key fingerprint of a DER certificate, as a client sees it on the wire."""
    cert = x509.load_der_x509_certificate(cert_der)
    return spki_fingerprint(spki_der(cert.public_key()))


# -- the enclave's side --------------------------------------------------------

class EnclaveTls:
    """The enclave's TLS key. Generated in memory, never written to disk."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.spki = spki_der(self._key.public_key())
        self.fingerprint = spki_fingerprint(self.spki)
        self.certificate_pem = ""

    def accept(self, certificate_pem: str) -> None:
        """Take a certificate the key server issued, if it is for our key."""
        try:
            cert = x509.load_pem_x509_certificate(certificate_pem.encode())
        except ValueError as exc:
            raise TlsError(f"unreadable certificate: {exc}") from exc
        if spki_der(cert.public_key()) != self.spki:
            raise TlsError("the certificate is for a different key")
        self.certificate_pem = certificate_pem

    def self_sign(self, name: str = "sentinel-enclave") -> None:
        """A certificate signed by our own key, for when no key server issued one.

        No CA vouches for it, so a client cannot rely on the certificate. It
        relies on the proof instead: every answer names this key's fingerprint
        under the chip's signature.
        """
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = _dt.datetime.now(_dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=LEAF_DAYS))
            .sign(self._key, hashes.SHA256())
        )
        self.certificate_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    def server_context(self) -> ssl.SSLContext:
        """A server context holding the key and certificate.

        `load_cert_chain` only reads files. On Linux the key goes through an
        anonymous in-memory file that never has a path on disk; elsewhere (tests
        on a laptop) through a temporary file removed straight after loading.
        """
        if not self.certificate_pem:
            raise TlsError("no certificate issued yet")
        key_pem = self._key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        bundle = key_pem + self.certificate_pem.encode()
        if hasattr(os, "memfd_create"):
            fd = os.memfd_create("sentinel-tls")
            try:
                os.write(fd, bundle)
                context.load_cert_chain(f"/proc/self/fd/{fd}")
            finally:
                os.close(fd)
        else:
            fd, path = tempfile.mkstemp()
            try:
                os.write(fd, bundle)
                os.close(fd)
                context.load_cert_chain(path)
            finally:
                os.unlink(path)
        return context


# -- the key server's side -----------------------------------------------------

def _san(name: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(name))
    except ValueError:
        return x509.DNSName(name)


class TlsIssuer:
    """Signs certificates for attested enclave keys with the customer's CA.

    The names on the certificate are the customer's choice, set when the key
    server starts. The enclave only supplies its key, so a miner cannot obtain
    a certificate for a name the customer did not pick.
    """

    def __init__(self, ca_cert_pem: bytes, ca_key_pem: bytes, names: list[str]) -> None:
        if not names:
            raise TlsError("give at least one host name or IP for the certificate")
        self.ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        self.ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
        self.names = list(names)

    @classmethod
    def from_dir(cls, directory: str | pathlib.Path, names: list[str]) -> "TlsIssuer":
        d = pathlib.Path(directory)
        return cls((d / "ca.crt").read_bytes(), (d / "ca.key").read_bytes(), names)

    def issue(self, spki_hex: str) -> str:
        try:
            public_key = serialization.load_der_public_key(bytes.fromhex(spki_hex))
        except ValueError as exc:
            raise TlsError(f"unreadable TLS key: {exc}") from exc
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise TlsError("the TLS key must be an EC key")
        now = _dt.datetime.now(_dt.timezone.utc)
        # Clients match the host against the SAN, not the CN, and a CN is capped
        # at 64 characters, which cloud internal host names exceed.
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sentinel enclave")]))
            .issuer_name(self.ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=LEAF_DAYS))
            .add_extension(x509.SubjectAlternativeName([_san(n) for n in self.names]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode()


def make_ca(directory: str | pathlib.Path, name: str = "Sentinel key server CA") -> pathlib.Path:
    """Create a CA key and certificate in `directory`. Refuses to overwrite."""
    d = pathlib.Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    key_path, cert_path = d / "ca.key", d / "ca.crt"
    if key_path.exists() or cert_path.exists():
        raise TlsError(f"{d} already holds a CA; refusing to overwrite it")
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path

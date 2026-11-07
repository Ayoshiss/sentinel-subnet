"""
Sealed credential release: the broker encrypts to the enclave, not to the wire.

Before this, a broker that decided to release sent the database credential back
in the clear, protected only by TLS. That is not enough against the party this
exists to defend against. The operator chooses the broker URL, so they can
point the miner at a relay of their own that forwards to the customer's real
broker. The real broker sees a genuine attestation, releases, and the relay
reads the credential on its way through. A valid certificate for the relay's
own domain is all it takes, and pinning a certificate inside the measured image
would mean a different image for every customer.

So the secret is sealed instead. The enclave makes a key pair in memory at
start, and binds the public half into the attestation it sends the broker. The
broker checks that attestation as before, then encrypts the credential to that
key. Only the measured code holds the private half, so a relay sees ciphertext
and nothing else, with or without TLS.

The broker also signs what it releases, and the enclave reports the broker's
key in every answer it attests afterwards. That replaces certificate pinning:
the miner can be pointed at any broker, but it cannot hide which one it used,
so a customer checks the key is their own. An operator who swaps in a broker of
their own gets answers that name a broker the customer never ran.

Construction: X25519 between a fresh ephemeral key and the enclave key, HKDF-
SHA256, AES-256-GCM with every public field as associated data, and an Ed25519
signature by the broker over the same fields and the ciphertext. Standard
pieces from `cryptography`, nothing new.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"sentinel sealed release v1"
_RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw


class SealingError(Exception):
    """A sealed release that does not open. Never carries the secret."""


def _public_hex(key) -> str:
    return key.public_bytes(*_RAW).hex()


def fingerprint(broker_key_hex: str) -> str:
    """How a broker is named in attested answers: SHA-256 of its public key."""
    return hashlib.sha256(bytes.fromhex(broker_key_hex)).hexdigest()


@dataclass(frozen=True)
class SealedCredential:
    """A credential only one enclave can open, signed by the broker that sent it."""

    resource: str
    nonce: str
    enclave_key: str
    broker_key: str
    ephemeral: str
    iv: str
    ciphertext: str
    signature: str

    def _header(self) -> bytes:
        """Every public field, canonically, for the AEAD and the signature."""
        fields = {k: v for k, v in asdict(self).items() if k not in ("ciphertext", "signature")}
        return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()

    def _signed(self) -> bytes:
        return self._header() + b"." + bytes.fromhex(self.ciphertext)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "SealedCredential":
        try:
            return cls(**{k: str(data[k]) for k in cls.__dataclass_fields__})
        except (KeyError, TypeError) as exc:
            raise SealingError(f"malformed sealed credential: {exc}") from exc


def _key(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(shared)


class BrokerIdentity:
    """The broker's signing key. Its public half is what customers check for."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._key = private_key or Ed25519PrivateKey.generate()

    @classmethod
    def load_or_create(cls, path) -> "BrokerIdentity":
        """A stable identity on disk, created once with owner-only permissions.

        Stable because customers recognise their broker by this key: a broker
        that changed it on every restart would look like an impostor.
        """
        import pathlib

        path = pathlib.Path(path)
        if path.exists():
            return cls(serialization.load_pem_private_key(path.read_bytes(), password=None))
        identity = cls()
        pem = identity._key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        return identity

    @property
    def public_hex(self) -> str:
        return _public_hex(self._key.public_key())

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_hex)

    def seal(self, secret: str, *, enclave_key: str, resource: str, nonce: str) -> SealedCredential:
        """Encrypt `secret` to `enclave_key` and sign the result."""
        try:
            recipient = X25519PublicKey.from_public_bytes(bytes.fromhex(enclave_key))
        except ValueError as exc:
            raise SealingError(f"enclave key is not an X25519 public key: {exc}") from exc
        ephemeral = X25519PrivateKey.generate()
        unsigned = SealedCredential(
            resource=resource, nonce=nonce, enclave_key=enclave_key,
            broker_key=self.public_hex, ephemeral=_public_hex(ephemeral.public_key()),
            iv=os.urandom(12).hex(), ciphertext="", signature="",
        )
        ciphertext = AESGCM(_key(ephemeral.exchange(recipient))).encrypt(
            bytes.fromhex(unsigned.iv), secret.encode(), unsigned._header()
        )
        sealed = SealedCredential(**{**asdict(unsigned), "ciphertext": ciphertext.hex()})
        return SealedCredential(**{**asdict(sealed), "signature": self._key.sign(sealed._signed()).hex()})


class EnclaveKey:
    """The enclave's decryption key. Generated in memory, never written anywhere."""

    def __init__(self) -> None:
        self._key = X25519PrivateKey.generate()

    @property
    def public_hex(self) -> str:
        return _public_hex(self._key.public_key())

    def open(self, sealed: SealedCredential, *, resource: str, nonce: str) -> tuple[str, str]:
        """(secret, broker fingerprint), or `SealingError`.

        Checks that the release answers this enclave, this resource and this
        nonce, that the broker named in it signed it, and that it decrypts. The
        broker is not checked against any list here: the enclave reports it,
        and the customer decides.
        """
        if sealed.enclave_key != self.public_hex:
            raise SealingError("sealed for a different enclave")
        if sealed.resource != resource or sealed.nonce != nonce:
            raise SealingError("sealed for a different request")
        try:
            broker = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sealed.broker_key))
            broker.verify(bytes.fromhex(sealed.signature), sealed._signed())
            ephemeral = X25519PublicKey.from_public_bytes(bytes.fromhex(sealed.ephemeral))
            secret = AESGCM(_key(self._key.exchange(ephemeral))).decrypt(
                bytes.fromhex(sealed.iv), bytes.fromhex(sealed.ciphertext), sealed._header()
            )
        except (InvalidSignature, InvalidTag, ValueError) as exc:
            raise SealingError(f"sealed credential does not open: {type(exc).__name__}") from exc
        return secret.decode(), fingerprint(sealed.broker_key)

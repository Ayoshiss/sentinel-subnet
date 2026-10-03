"""
API keys, for callers who are not on Bittensor.

The subnet authenticates callers by hotkey signature, which is right for
validators and impossible for everyone else: a bank deploying Sentinel over its
own database has no hotkey and is never going to get one. Without another way
in, the self-hosted product cannot be used by the people it is for.

Two properties this file exists to guarantee.

**Only hashes are stored.** The file an operator keeps on disk holds SHA-256
digests, never the keys themselves. If it leaks, nothing in it can be presented
as a credential. Minting a key prints it once and then it is unrecoverable,
which is the correct trade: a key you can look up later is a key an attacker can
look up later.

**Comparison is constant time.** Comparing digests with `==` leaks their shared
prefix through timing, which over enough requests is a key.

What an API key does NOT give you, stated plainly because the hotkey path does
give it: freshness. A signed request carries a nonce and a timestamp, so it
cannot be replayed. A bearer token has no such property, so anyone who captures
a request can repeat it. Over TLS against read-only tools that is usually
acceptable; it is not equivalent, and an operator should know which they chose.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import pathlib
import secrets


class ApiKeyError(Exception):
    pass


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def mint() -> tuple[str, str]:
    """A new key and its digest. The key is returned once and never stored."""
    key = "sk_sentinel_" + secrets.token_urlsafe(32)
    return key, hash_key(key)


class ApiKeyStore:
    """Labelled key digests. Labels exist so one key can be revoked by name."""

    def __init__(self, digests: dict[str, object]) -> None:
        # Two accepted shapes. "label": "<digest>" means the key may reach every
        # scope, which is the right default for a single-database deployment.
        # "label": {"digest": ..., "scopes": [...]} restricts it, so a key for a
        # support agent cannot read the payments scope even though the same
        # enclave serves both.
        self._scopes: dict[str, frozenset[str] | None] = {}
        flat: dict[str, str] = {}
        for label, value in digests.items():
            if isinstance(value, dict):
                flat[label] = str(value.get("digest", ""))
                scopes = value.get("scopes")
                self._scopes[label] = frozenset(scopes) if scopes else None
            else:
                flat[label] = str(value)
                self._scopes[label] = None
        digests = flat
        for label, digest in digests.items():
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
                raise ApiKeyError(
                    f"key {label!r} is not a sha256 digest. This file holds "
                    "hashes, not keys: if it held keys, leaking it would hand "
                    "over every credential."
                )
        self._digests = {label: digest.lower() for label, digest in digests.items()}

    @classmethod
    def from_file(cls, path: str | pathlib.Path) -> "ApiKeyStore":
        p = pathlib.Path(path).expanduser()
        try:
            data = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ApiKeyError(f"could not read API keys from {p}: {exc}") from exc
        if not isinstance(data, dict) or not data:
            raise ApiKeyError(
                f"{p} must be an object of label -> sha256 digest, and not empty. "
                "An empty store would authenticate nobody while looking configured."
            )
        return cls(data)

    def label_for(self, presented: str) -> str | None:
        """The label this key belongs to, or None.

        Every entry is compared even after a match, so the time taken does not
        depend on which key was presented or how many are configured.
        """
        candidate = hash_key(presented)
        found: str | None = None
        for label, digest in self._digests.items():
            if hmac.compare_digest(candidate, digest):
                found = label
        return found

    def scopes_for(self, label: str) -> frozenset[str] | None:
        """Which scopes this key may reach. None means all of them."""
        return self._scopes.get(label)

    def __len__(self) -> int:
        return len(self._digests)

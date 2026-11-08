"""
Start the miner in the measured image, configured from GCP instance metadata.

The measured image has no shell, no SSH and no guest agent, so an operator
cannot log in and edit what runs. What an operator still has to choose, their
hotkey, their broker, who may call them, arrives as instance metadata under
the attribute `sentinel-miner`, as JSON.

Metadata is data, never code. Only the keys below are read, each must have the
expected type, and no value may begin with "-", so nothing in metadata can add
a flag the image did not intend. Anything else is refused and the miner does
not start, which is a louder failure than ignoring it.

    {"hotkey_ss58": "5...", "measurement": "<uki digest>",
     "allow_hotkey": ["5..."], "broker_url": "https://...", "scope": ["db"]}

A pilot customer's agent is not on Bittensor, so it calls with an API key.
`api_keys` carries the SHA-256 digests from scripts/make_api_key.py, never the
keys themselves: metadata is readable by the operator, and a digest is useless
to them.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import sys
import urllib.request

METADATA_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/sentinel-miner"
)
ROOT = pathlib.Path(__file__).resolve().parent.parent

#: key: (type, flag). Lists repeat the flag; booleans add it when true.
FIELDS: dict[str, tuple[type, str]] = {
    "hotkey_ss58": (str, "--hotkey-ss58"),
    "measurement": (str, "--measurement"),
    "netuid": (int, "--netuid"),
    "endpoint": (str, "--endpoint"),
    "port": (int, "--port"),
    "allow_hotkey": (list, "--allow-hotkey"),
    "no_allow_validators": (bool, "--no-allow-validators"),
    "broker_url": (str, "--broker-url"),
    "broker_insecure": (bool, "--broker-insecure"),
    "scope": (list, "--scope"),
    "tdx_mrtd": (list, "--tdx-mrtd"),
    "tdx_db_cert_b64": (str, "--tdx-db-cert"),
    "api_keys": (dict, "--api-keys"),
}
REQUIRED = ("hotkey_ss58", "measurement")


class ConfigError(Exception):
    pass


def _value(key: str, value: object) -> str:
    text = str(value)
    if not text or text.startswith("-") or any(c.isspace() for c in text):
        raise ConfigError(f"{key}: {text!r} is not an acceptable value")
    return text


def argv_from(config: dict, cert_path: pathlib.Path) -> list[str]:
    """The run_miner.py arguments for `config`, or `ConfigError`."""
    unknown = set(config) - set(FIELDS)
    if unknown:
        raise ConfigError(f"unknown keys {sorted(unknown)}")
    missing = [k for k in REQUIRED if not config.get(k)]
    if missing:
        raise ConfigError(f"missing {missing}")

    # The image never publishes to chain itself: it holds no wallet. TLS is not
    # an option here: the operator writes the metadata, and must not be able to
    # make the miner serve API keys and results in the clear.
    argv = ["--no-chain", "--tls"]
    for key, value in config.items():
        kind, flag = FIELDS[key]
        if kind is bool:
            if not isinstance(value, bool):
                raise ConfigError(f"{key} must be true or false")
            if value:
                argv.append(flag)
        elif kind is list:
            if not isinstance(value, list):
                raise ConfigError(f"{key} must be a list")
            for item in value:
                argv += [flag, _value(key, item)]
        elif kind is int:
            if isinstance(value, bool) or not isinstance(value, int):
                raise ConfigError(f"{key} must be an integer")
            argv += [flag, str(value)]
        elif kind is dict:
            argv += [flag, str(_write_api_keys(value, cert_path.with_name("api-keys.json")))]
        elif key == "tdx_db_cert_b64":
            try:
                cert_path.write_bytes(base64.b64decode(str(value), validate=True))
            except ValueError as exc:
                raise ConfigError(f"{key} is not base64: {exc}") from exc
            argv += [flag, str(cert_path)]
        else:
            if not isinstance(value, str):
                raise ConfigError(f"{key} must be a string")
            argv += [flag, _value(key, value)]
    return argv


def _write_api_keys(value: object, path: pathlib.Path) -> pathlib.Path:
    """Check the digests the same way the miner will, then write them out."""
    sys.path.insert(0, str(ROOT))
    from sentinel.serving.apikeys import ApiKeyError, ApiKeyStore

    if not isinstance(value, dict) or not value:
        raise ConfigError("api_keys must be a non-empty object of label -> digest")
    try:
        ApiKeyStore(value)
    except ApiKeyError as exc:
        raise ConfigError(f"api_keys: {exc}") from exc
    path.write_text(json.dumps(value))
    return path


def fetch() -> dict:
    request = urllib.request.Request(METADATA_URL, headers={"Metadata-Flavor": "Google"})
    with urllib.request.urlopen(request, timeout=10) as response:
        config = json.loads(response.read())
    if not isinstance(config, dict):
        raise ConfigError("sentinel-miner metadata must be a JSON object")
    return config


def main() -> int:
    runtime = pathlib.Path(os.environ.get("RUNTIME_DIRECTORY", "/run/sentinel"))
    runtime.mkdir(parents=True, exist_ok=True)
    try:
        argv = argv_from(fetch(), runtime / "db.der")
    except (ConfigError, OSError, ValueError) as exc:
        print(f"sentinel-miner metadata refused: {exc}", file=sys.stderr)
        return 2
    script = str(ROOT / "scripts" / "run_miner.py")
    os.execv(sys.executable, [sys.executable, script, *argv])
    return 0  # unreachable


if __name__ == "__main__":
    raise SystemExit(main())

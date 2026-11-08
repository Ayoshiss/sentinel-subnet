"""The measured image's only configuration path: metadata as data, never flags."""

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("miner_from_metadata", ROOT / "scripts" / "miner_from_metadata.py")
launcher = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(launcher)

BASE = {"hotkey_ss58": "5CA3onFp", "measurement": "c13d7aa6"}


def argv(config, tmp_path):
    return launcher.argv_from(config, tmp_path / "db.der")


def test_the_minimum_config_serves_without_a_wallet(tmp_path):
    assert argv(BASE, tmp_path) == ["--no-chain", "--tls", "--hotkey-ss58", "5CA3onFp", "--measurement", "c13d7aa6"]


def test_lists_repeat_and_booleans_add_the_flag(tmp_path):
    out = argv({**BASE, "allow_hotkey": ["5A", "5B"], "no_allow_validators": True, "port": 8091}, tmp_path)
    assert out[-7:] == ["--allow-hotkey", "5A", "--allow-hotkey", "5B", "--no-allow-validators", "--port", "8091"]


def test_the_db_certificate_is_written_to_a_file(tmp_path):
    out = argv({**BASE, "tdx_db_cert_b64": "AAEC"}, tmp_path)
    assert out[-2:] == ["--tdx-db-cert", str(tmp_path / "db.der")]
    assert (tmp_path / "db.der").read_bytes() == b"\x00\x01\x02"


def test_api_key_digests_are_written_for_non_bittensor_callers(tmp_path):
    import json

    keys = {"pilot-agent": "ab" * 32, "support": {"digest": "cd" * 32, "scopes": ["support"]}}
    out = argv({**BASE, "api_keys": keys}, tmp_path)
    assert out[-2:] == ["--api-keys", str(tmp_path / "api-keys.json")]
    assert json.loads((tmp_path / "api-keys.json").read_text()) == keys


@pytest.mark.parametrize("config, reason", [
    ({**BASE, "api_keys": {"agent": "not-a-digest"}}, "sha256 digest"),
    ({**BASE, "api_keys": {}}, "non-empty"),
    ({**BASE, "api_keys": ["ab" * 32]}, "non-empty"),
    ({**BASE, "allow_any": True}, "unknown keys"),
    ({**BASE, "allow_mock": True}, "unknown keys"),
    ({"hotkey_ss58": "5A"}, "missing"),
    ({**BASE, "allow_hotkey": ["--allow-any"]}, "not an acceptable value"),
    ({**BASE, "broker_url": "https://x --allow-any"}, "not an acceptable value"),
    ({**BASE, "port": "8091"}, "integer"),
    ({**BASE, "port": True}, "integer"),
    ({**BASE, "no_allow_validators": "yes"}, "true or false"),
    ({**BASE, "scope": "db"}, "must be a list"),
    ({**BASE, "tdx_db_cert_b64": "%%%"}, "base64"),
])
def test_metadata_cannot_add_a_flag_the_image_did_not_intend(config, reason, tmp_path):
    with pytest.raises(launcher.ConfigError, match=reason):
        argv(config, tmp_path)

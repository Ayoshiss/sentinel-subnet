"""
Guards on the measured image's definition (image/).

The image is only as good as a few lines of config. These pin the ones whose
quiet regression would undo the point: everything from one dated snapshot, a
verity root, nothing to log in with, and metadata read only as data.
"""

import configparser
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMAGE = ROOT / "image"


def mkosi_conf() -> str:
    return (IMAGE / "mkosi.conf").read_text()


def setting(name: str) -> str:
    match = re.search(rf"^{name}=(.*)$", mkosi_conf(), re.M)
    assert match, name
    return match.group(1).strip()


def packages() -> set[str]:
    block = re.search(r"^Packages=\n((?:\s+\S+\n)+)", mkosi_conf(), re.M).group(1)
    return {line.strip() for line in block.splitlines()}


def test_every_package_source_is_the_same_dated_snapshot():
    snapshot = setting("Mirror")
    assert re.fullmatch(r"https://snapshot\.ubuntu\.com/ubuntu/\d{8}T\d{6}Z", snapshot)
    assert setting("ToolsTreeMirror") == snapshot
    sources = (IMAGE / "mkosi.sandbox/etc/apt/sources.list.d/mkosi.sources").read_text()
    assert f"URIs: {snapshot}" in sources
    assert "noble-security" in sources, "security must come from the snapshot, not the live archive"
    assert "security.ubuntu.com" not in sources


def test_the_build_is_pinned_for_reproducibility():
    assert setting("SourceDateEpoch").isdigit()
    assert re.fullmatch(r"[0-9a-f-]{36}", setting("Seed"))
    lock = (IMAGE / "requirements.lock").read_text()
    pins = re.findall(r"^([a-z0-9_.-]+)==", lock, re.M | re.I)
    assert "dcap-qvl" in pins and "bittensor" in pins
    assert lock.count("--hash=sha256:") >= len(pins)
    assert "--require-hashes --only-binary=:all:" in (IMAGE / "mkosi.build.chroot").read_text()


def test_the_root_is_verity_protected_and_the_command_line_does_not_name_it():
    root = configparser.ConfigParser()
    root.read(IMAGE / "mkosi.repart/10-root.conf")
    verity = configparser.ConfigParser()
    verity.read(IMAGE / "mkosi.repart/20-root-verity.conf")
    assert root["Partition"]["Verity"] == "data"
    assert root["Partition"]["Format"] == "erofs"
    assert verity["Partition"]["Verity"] == "hash"
    cmdline = setting("KernelCommandLine")
    # mkosi adds roothash=; a root= here would bypass verity discovery.
    assert "root=" not in cmdline.replace("roothash=", "")
    assert "systemd.volatile=state" in cmdline
    assert setting("Bootloader") == "uki"


def test_there_is_no_way_in():
    banned = {"openssh-server", "google-guest-agent", "google-compute-engine", "cloud-init", "sudo"}
    assert not packages() & banned
    postinst = (IMAGE / "mkosi.postinst.chroot").read_text()
    for unit in ("getty@.service", "serial-getty@.service", "debug-shell.service", "emergency.service"):
        assert unit in postinst
    assert "passwd -l root" in postinst


def test_the_miner_starts_from_metadata_and_nothing_else():
    unit = (IMAGE / "mkosi.extra/etc/systemd/system/sentinel-miner.service").read_text()
    exec_start = re.search(r"^ExecStart=(.*)$", unit, re.M).group(1)
    assert exec_start == "/opt/sentinel/.venv/bin/python /opt/sentinel/scripts/miner_from_metadata.py"

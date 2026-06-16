"""Isolation guard for E5 full_sweep build — external binaries must not change."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PRODUCTION_HOST = Path("/root/arguzz/workspace/output/target/release/risc0-host")
MINIMAL_ADD_HOST = (
    Path(__file__).resolve().parents[1]
    / "minimal_add"
    / "target"
    / "release"
    / "thesis-minimal-host"
)
MINIMAL_ADD_FROZEN_SHA = (
    "5337f9448d7946c5785f1506b0fbfbfa07d32d6542e60c9cc158a22ce0611d23"
)
FULL_SWEEP_HOST = ROOT / "target" / "release" / "thesis-full-sweep-host"
FROZEN_DIR = ROOT / "frozen_host"
FROZEN_COPY = FROZEN_DIR / "thesis-full-sweep-host.e0frozen"
SHA256_FILE = FROZEN_DIR / "SHA256"


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def file_mtime(path: Path) -> int:
    return int(path.stat().st_mtime)


def snapshot_external() -> dict:
    snap = {}
    for label, path in (
        ("production_host", PRODUCTION_HOST),
        ("minimal_add_host", MINIMAL_ADD_HOST),
    ):
        if not path.exists():
            raise SystemExit(f"missing guard path: {path}")
        snap[label] = {"path": str(path), "mtime": file_mtime(path), "sha256": file_sha256(path)}
    if snap["minimal_add_host"]["sha256"] != MINIMAL_ADD_FROZEN_SHA:
        raise SystemExit(
            f"minimal_add host sha drift: {snap['minimal_add_host']['sha256']} "
            f"!= {MINIMAL_ADD_FROZEN_SHA}"
        )
    return snap


def assert_external_unchanged(before: dict) -> None:
    after = snapshot_external()
    for key in before:
        if before[key]["mtime"] != after[key]["mtime"]:
            raise SystemExit(
                f"EXTERNAL BINARY MTIME CHANGED: {key} "
                f"{before[key]['mtime']} -> {after[key]['mtime']}"
            )
        if before[key]["sha256"] != after[key]["sha256"]:
            raise SystemExit(f"EXTERNAL BINARY SHA CHANGED: {key}")


def freeze_full_sweep_host(host: Path = FULL_SWEEP_HOST) -> str:
    if not host.exists():
        raise SystemExit(f"full_sweep host missing: {host} — run ./build.sh first")
    sha = file_sha256(host)
    FROZEN_DIR.mkdir(parents=True, exist_ok=True)
    data = host.read_bytes()
    FROZEN_COPY.write_bytes(data)
    FROZEN_COPY.chmod(0o755)
    SHA256_FILE.write_text(sha + "\n")
    (FROZEN_DIR / "guard_snapshot.json").write_text(json.dumps(snapshot_external(), indent=2))
    return sha


def assert_frozen_full_sweep(host: Path = FROZEN_COPY) -> str:
    if not SHA256_FILE.exists():
        raise SystemExit(f"missing {SHA256_FILE} — run freeze after build")
    expected = SHA256_FILE.read_text().strip()
    sha = file_sha256(host)
    if sha != expected:
        raise SystemExit(f"frozen full_sweep sha mismatch: got {sha} expected {expected}")
    return sha

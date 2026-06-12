"""Frozen thesis-minimal-host sha guard (E0/E1/E2/E3)."""

from __future__ import annotations

import hashlib
from pathlib import Path

FROZEN_HOST_SHA256 = (
    "5337f9448d7946c5785f1506b0fbfbfa07d32d6542e60c9cc158a22ce0611d23"
)
DEFAULT_HOST = (
    Path(__file__).resolve().parent / "target" / "release" / "thesis-minimal-host"
)
FROZEN_COPY = (
    Path(__file__).resolve().parent / "frozen_host" / "thesis-minimal-host.e0frozen"
)


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def assert_frozen_host(
    host: Path = DEFAULT_HOST,
    expected_sha: str = FROZEN_HOST_SHA256,
) -> str:
    if not host.exists():
        raise SystemExit(
            f"host missing: {host} — rebuild forbidden by amendment; "
            f"restore from {FROZEN_COPY}"
        )
    sha = file_sha256(host)
    if sha != expected_sha:
        raise SystemExit(
            f"host sha mismatch: got {sha}, expected {expected_sha}. "
            f"Do NOT auto-rebuild; restore frozen copy at {FROZEN_COPY}"
        )
    return sha

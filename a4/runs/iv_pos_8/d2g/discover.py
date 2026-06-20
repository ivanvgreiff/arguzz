"""Discover D2.F campaign DBs from a collection root (smoke or production)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

D2F_VARIANTS: Tuple[str, ...] = (
    "V5_control",
    "V6_uniform",
    "V6_cTS",
    "Hybrid_cTS",
)

_RUN_DIR_RE = re.compile(
    r"^pos_iv_pos_8_d2f_(?P<variant>.+)_seed(?P<seed>\d+)_n(?P<n>\d+)$"
)


def parse_d2f_run_dir(run_dir: Path) -> Tuple[str, int, int]:
    """Return (variant, seed, N) from a D2.F run directory name."""
    m = _RUN_DIR_RE.match(run_dir.name)
    if not m:
        raise ValueError(f"not a D2.F run dir: {run_dir.name}")
    return m.group("variant"), int(m.group("seed")), int(m.group("n"))


def _run_dir_complete(run_dir: Path) -> bool:
    db = run_dir / "run.db"
    if not db.is_file():
        return False
    meta = run_dir / "meta.json"
    if meta.is_file():
        try:
            data = json.loads(meta.read_text())
            if data.get("exit_code") in (0, 2) and data.get("ended_at_epoch"):
                return True
        except (json.JSONDecodeError, OSError):
            pass
    if any(run_dir.glob(".OK")) or any(run_dir.parent.glob(".OK")):
        return True
    # Local smoke pulls may only have run.db — accept if non-empty.
    return db.stat().st_size > 4096


def discover_d2f_dbs(
    collection_root: Path,
    *,
    variants: Tuple[str, ...] = D2F_VARIANTS,
) -> Dict[str, Dict[int, Path]]:
    """Map variant -> seed -> run.db path (newest wins per pair)."""
    found: Dict[str, Dict[int, Path]] = {v: {} for v in variants}
    for db in sorted(collection_root.rglob("run.db")):
        try:
            variant, seed, _n = parse_d2f_run_dir(db.parent)
        except ValueError:
            continue
        if variant not in found:
            continue
        if not _run_dir_complete(db.parent):
            continue
        prev = found[variant].get(seed)
        if prev is None or db.stat().st_mtime >= prev.stat().st_mtime:
            found[variant][seed] = db
    return found


def flat_db_list(
    collection_root: Path,
    *,
    variants: Tuple[str, ...] = D2F_VARIANTS,
) -> List[Path]:
    mapping = discover_d2f_dbs(collection_root, variants=variants)
    out: List[Path] = []
    for variant in variants:
        for seed in sorted(mapping[variant]):
            out.append(mapping[variant][seed])
    return out

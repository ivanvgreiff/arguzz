"""Discover IV.POS.7 production DBs (V0–V6 × seeds).

V1–V5: Pro-facing R2 set (50 DBs).
V0/V6: Internal track — uniform random floor + arguzz baseline.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

# Longest selector first to avoid partial matches.
SELECTOR_TO_VARIANT: List[Tuple[str, str]] = [
    ("cTS_semantic_v2_decayexp", "V5-decayexp"),
    ("cTS_semantic_v2_decayepoch", "V5-decayepoch"),
    ("cTS_semantic_v2", "V5"),
    ("kindUCB_zoned_v2_noQ", "V3"),
    ("kindUCB_zoned_v1", "V2"),
    ("kindTS_zoned_v2", "V4"),
    ("uniform", "V0"),
    ("arguzz", "V6"),
    ("zoned", "V1"),
]

VARIANT_TO_SELECTOR = {v: s for s, v in SELECTOR_TO_VARIANT}
VARIANT_TO_PRO_NAME = {
    "V0": "uniform_random",
    "V1": "zoned_current",
    "V2": "kind_UCB + zoned_step + current_reward",
    "V3": "kind_UCB + zoned_step + no_Qloc_reward",
    "V4": "kind_TS + zoned_step + discovery_reward",
    "V5": "constrained_TS + semantic_zones + discovery_reward",
    "V5-decayexp": "cTS_semantic_v2_decayexp",
    "V5-decayepoch": "cTS_semantic_v2_decayepoch",
    "V6": "arguzz",
}

# Pro-facing R2 variants only.
R2_VARIANTS: Tuple[str, ...] = ("V1", "V2", "V3", "V4", "V5")
# Full internal analysis set.
ALL_VARIANTS_ORDER: Tuple[str, ...] = ("V0", "V1", "V2", "V3", "V4", "V5", "V6")
INTERNAL_ONLY_VARIANTS: Tuple[str, ...] = ("V0", "V6")

V6_EXPECTED_SEEDS = 10

DEFAULT_DBS_ROOT = Path(__file__).resolve().parents[1] / "dbs"


def parse_db_path(db_path: Path) -> Tuple[str, str, int, str]:
    """Return (variant V0..V6, selector, seed, db_path_str)."""
    name = db_path.name
    variant = selector = None
    for sel, var in SELECTOR_TO_VARIANT:
        if sel in name:
            variant, selector = var, sel
            break
    if variant is None:
        raise ValueError(f"cannot parse selector from {db_path}")
    m = re.search(r"seed(\d+)", name)
    if not m:
        raise ValueError(f"cannot parse seed from {db_path}")
    return variant, selector, int(m.group(1)), str(db_path)


def _meta_json_exit_ok(db_path: Path) -> bool:
    """True if sibling meta.json records exit_code == 0 (coinbase completion signal)."""
    meta = db_path.parent / "meta.json"
    if not meta.is_file():
        return False
    try:
        data = json.loads(meta.read_text())
        return data.get("exit_code") == 0 and data.get("ended_at_epoch") is not None
    except (json.JSONDecodeError, OSError):
        return False


def _run_dir_has_ok_marker(db_path: Path) -> bool:
    """True if a .OK completion marker exists in the DB run directory tree."""
    for d in (db_path.parent, db_path.parent.parent):
        if any(d.glob("*.OK")):
            return True
    return False


def _is_completed_db(db_path: Path, variant: str) -> bool:
    """V6 in-flight DBs may exist without completion — skip unless marked done."""
    if variant != "V6":
        return True
    return _run_dir_has_ok_marker(db_path) or _meta_json_exit_ok(db_path)


def discover_dbs(
    dbs_root: Path = DEFAULT_DBS_ROOT,
    *,
    variants: Tuple[str, ...] | None = None,
) -> Dict[str, Dict[int, Path]]:
    """Map variant -> seed -> db_path (newest file wins per pair)."""
    active_variants = variants or tuple(v for _, v in SELECTOR_TO_VARIANT)
    found: Dict[str, Dict[int, Path]] = {v: {} for v in active_variants}
    for db in sorted(dbs_root.rglob("*.db")):
        try:
            variant, _, seed, _ = parse_db_path(db)
        except ValueError:
            continue
        if variant not in found:
            continue
        if not _is_completed_db(db, variant):
            continue
        prev = found[variant].get(seed)
        if prev is None or db.stat().st_mtime >= prev.stat().st_mtime:
            found[variant][seed] = db
    return found


def discover_status(dbs_root: Path = DEFAULT_DBS_ROOT) -> Dict[str, object]:
    """Summary flags for internal track (V0/V6 completeness)."""
    m = discover_dbs(dbs_root, variants=ALL_VARIANTS_ORDER)
    v0_count = len(m["V0"])
    v6_count = len(m["V6"])
    return {
        "v0_seed_count": v0_count,
        "v0_complete": v0_count == 10,
        "v6_seed_count": v6_count,
        "v6_expected_seeds": V6_EXPECTED_SEEDS,
        "v6_partial": v6_count < V6_EXPECTED_SEEDS,
    }


def flat_db_list(
    dbs_root: Path = DEFAULT_DBS_ROOT,
    *,
    variants: Tuple[str, ...] = R2_VARIANTS,
) -> List[Path]:
    """Paths in stable (variant, seed) order."""
    m = discover_dbs(dbs_root, variants=variants)
    out: List[Path] = []
    for variant in variants:
        for seed in sorted(m[variant]):
            out.append(m[variant][seed])
    return out


def internal_flat_db_list(dbs_root: Path = DEFAULT_DBS_ROOT) -> List[Path]:
    """V0–V6 paths in stable order (internal metrics build)."""
    return flat_db_list(dbs_root, variants=ALL_VARIANTS_ORDER)

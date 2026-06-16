"""Phase 9.1 primary metrics — single source of truth for IV.POS.7 analysis."""
from __future__ import annotations

import math
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import numpy as np
import pandas as pd

from .discover import ALL_VARIANTS_ORDER, R2_VARIANTS, discover_dbs, parse_db_path
from .zone_cache import step_to_zone_map

N_MUTATIONS = 6000
TIME_THRESHOLDS = (40, 43, 46)
REFERENCE_VARIANT = "V1"


def _shannon_entropy(counts: Counter) -> float:
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    ent = 0.0
    for c in counts.values():
        if c > 0:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def _coverage_curve(first_hits: Sequence[int], n: int = N_MUTATIONS) -> np.ndarray:
    """Cumulative unique local contexts discovered by mutation t (Pro §10 AUC input)."""
    y = np.zeros(n + 1, dtype=int)
    for fh in first_hits:
        if 1 <= fh <= n:
            y[fh] += 1
    return np.cumsum(y)[1:]


def _time_to_threshold(curve: np.ndarray, threshold: int) -> Optional[int]:
    """First mutation index (1-based) reaching threshold contexts; None if never."""
    hits = np.where(curve >= threshold)[0]
    if len(hits) == 0:
        return None
    return int(hits[0]) + 1


def _read_first_hits(conn: sqlite3.Connection) -> List[int]:
    """First-hit mutation ids from legacy `coverage` table (IV.POS.5 / 46-context universe)."""
    try:
        return [int(r[0]) for r in conn.execute(
            "SELECT first_hit_mutation_id FROM coverage ORDER BY first_hit_mutation_id"
        ).fetchall()]
    except sqlite3.OperationalError:
        return []


def _read_constraint_locs(conn: sqlite3.Connection) -> Set[str]:
    try:
        return {r[0] for r in conn.execute("SELECT constraint_loc FROM coverage").fetchall()}
    except sqlite3.OperationalError:
        return set()


def _zone_entropy_from_mutations(conn: sqlite3.Connection) -> float:
    """Zone allocation entropy from mutation steps (V1 zoned + any variant without bandit zones)."""
    s2z = step_to_zone_map()
    zone_counts: Counter = Counter()
    for (step,) in conn.execute("SELECT step FROM mutations").fetchall():
        zone = s2z.get(int(step), "unclassified")
        zone_counts[zone] += 1
    return _shannon_entropy(zone_counts)


def _zone_entropy_from_bandit(conn: sqlite3.Connection) -> Optional[float]:
    zone_counts: Counter = Counter()
    try:
        rows = conn.execute("SELECT selected_arm FROM bandit_decisions").fetchall()
    except sqlite3.OperationalError:
        return None
    if not rows:
        return None
    for (arm,) in rows:
        if arm and "|" in arm:
            parts = arm.split("|")
            if len(parts) >= 2:
                zone_counts[parts[1]] += 1
    return _shannon_entropy(zone_counts) if zone_counts else None


def build_v1_constraint_union(dbs_root: Optional[Path] = None) -> Set[str]:
    """Union of all constraint_locs hit by V1 (zoned) across 10 seeds — baseline for Criterion 5."""
    m = discover_dbs(dbs_root) if dbs_root else discover_dbs()
    union: Set[str] = set()
    for db in m[REFERENCE_VARIANT].values():
        with sqlite3.connect(db) as conn:
            union |= _read_constraint_locs(conn)
    return union


def compute_metrics_for_db(
    db_path: Path,
    *,
    n: int = N_MUTATIONS,
    v1_union: Optional[Set[str]] = None,
) -> Dict[str, object]:
    """Compute one row of Phase 9.1 metrics for a single DB."""
    variant, selector, seed, _ = parse_db_path(db_path)
    with sqlite3.connect(db_path) as conn:
        first_hits = _read_first_hits(conn)
        curve = _coverage_curve(first_hits, n=n)
        local_final = int(curve[-1]) if len(curve) else 0
        auc = float(np.trapezoid(curve, dx=1.0)) if len(curve) else 0.0

        times = {f"time_to_{t}": _time_to_threshold(curve, t) for t in TIME_THRESHOLDS}
        all_46_hit = bool(local_final >= 46)

        locs = _read_constraint_locs(conn)
        if v1_union is not None:
            novel = sorted(locs - v1_union)
            novel_locs_vs_v1 = len(novel)
            novel_locs_names = ";".join(novel)
        else:
            novel_locs_vs_v1 = 0
            novel_locs_names = ""

        try:
            lc_v2_final = int(conn.execute(
                "SELECT COUNT(*) FROM local_coverage_v2"
            ).fetchone()[0])
        except sqlite3.OperationalError:
            lc_v2_final = float("nan")

        try:
            cgc = int(conn.execute(
                "SELECT COUNT(*) FROM compressed_global_coverage"
            ).fetchone()[0])
        except sqlite3.OperationalError:
            cgc = 0

        n_mut = int(conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0])
        try:
            n_crash = int(conn.execute(
                "SELECT COUNT(*) FROM mutation_rewards WHERE mode='crash'"
            ).fetchone()[0])
            crash_rate = (n_crash / n_mut) if n_mut else 0.0
        except sqlite3.OperationalError:
            crash_rate = float("nan")

        try:
            n_no_effect = int(conn.execute("""
                SELECT COUNT(*) FROM mutation_rewards
                WHERE mode='normal' AND T_new=0 AND F_new=0 AND S=0 AND d_loc=0 AND d_glob=0
            """).fetchone()[0])
            no_effect_rate = (n_no_effect / n_mut) if n_mut else 0.0
        except sqlite3.OperationalError:
            no_effect_rate = float("nan")

        kind_counts = Counter(
            r[0] for r in conn.execute("SELECT kind FROM mutations").fetchall()
        )
        alloc_entropy_kind = _shannon_entropy(kind_counts)

        # Zone entropy: bandit arm zones when present; else mutation step → zone_classifier.
        bandit_zone_ent = _zone_entropy_from_bandit(conn)
        alloc_entropy_zone = (
            bandit_zone_ent if bandit_zone_ent is not None
            else _zone_entropy_from_mutations(conn)
        )

        cp = conn.execute("SELECT selector FROM campaign_params LIMIT 1").fetchone()
        db_selector = cp[0] if cp else selector

    return {
        "variant": variant,
        "selector": db_selector,
        "seed": seed,
        "db_path": str(db_path),
        "local_context_final": local_final,
        "local_coverage_v2_final": lc_v2_final,
        "local_context_AUC": auc,
        **times,
        "all_46_hit": all_46_hit,
        "compressed_global_context_final": cgc,
        "crash_rate": crash_rate,
        "no_effect_rate": no_effect_rate,
        "allocation_entropy_by_kind": alloc_entropy_kind,
        "allocation_entropy_by_zone": alloc_entropy_zone,
        "novel_locs_vs_v1": novel_locs_vs_v1,
        "novel_locs_names_vs_v1": novel_locs_names,
        "n_mutations": n_mut,
    }


def _collect_db_paths(
    dbs_root: Optional[Path],
    variants: Tuple[str, ...],
) -> List[Path]:
    m = discover_dbs(dbs_root, variants=variants) if dbs_root else discover_dbs(variants=variants)
    paths: List[Path] = []
    for variant in variants:
        for seed in sorted(m.get(variant, {})):
            paths.append(m[variant][seed])
    return paths


def compute_metrics_frame(
    db_paths: Optional[Iterable[Path]] = None,
    dbs_root: Optional[Path] = None,
    *,
    variants: Tuple[str, ...] = R2_VARIANTS,
) -> pd.DataFrame:
    """DataFrame with one row per (variant, seed). Default: R2 set V1–V5."""
    v1_union = build_v1_constraint_union(dbs_root)
    if db_paths is None:
        db_paths = _collect_db_paths(dbs_root, variants)
    rows = [compute_metrics_for_db(Path(p), v1_union=v1_union) for p in db_paths]
    df = pd.DataFrame(rows)

    # Per-variant union novel locs vs V1 (for success_criteria Criterion 5).
    variant_novel_union: Dict[str, int] = {}
    for variant in df["variant"].unique():
        locs: Set[str] = set()
        for _, row in df[df["variant"] == variant].iterrows():
            if row["novel_locs_names_vs_v1"]:
                locs.update(row["novel_locs_names_vs_v1"].split(";"))
        variant_novel_union[variant] = len(locs)
    df["novel_locs_union_vs_v1"] = df["variant"].map(variant_novel_union)
    return df


def compute_internal_metrics_frame(
    dbs_root: Optional[Path] = None,
) -> pd.DataFrame:
    """V0–V6 metrics frame for internal track (does not touch R2 CSVs)."""
    return compute_metrics_frame(dbs_root=dbs_root, variants=ALL_VARIANTS_ORDER)


def aggregate_by_variant(df: pd.DataFrame) -> pd.DataFrame:
    """Mean/std per variant for numeric Phase 9.1 columns."""
    numeric = [
        "local_context_final", "local_coverage_v2_final", "local_context_AUC",
        "time_to_40", "time_to_43", "time_to_46",
        "compressed_global_context_final",
        "crash_rate", "no_effect_rate",
        "allocation_entropy_by_kind", "allocation_entropy_by_zone",
        "novel_locs_vs_v1",
    ]
    agg = df.groupby("variant")[numeric].agg(["mean", "std", "count"])
    agg.columns = ["_".join(c).strip("_") for c in agg.columns]
    agg["all_46_hit_rate"] = df.groupby("variant")["all_46_hit"].mean()
    agg["novel_locs_union_vs_v1"] = df.groupby("variant")["novel_locs_union_vs_v1"].first()
    return agg.reset_index()

"""V6 partial preview — comparison vs V1/V5, loc overlap, apples-to-apples fairness."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd

from .constraint_loc_normalize import normalize_constraint_loc, read_normalized_constraint_locs
from .discover import discover_dbs
from .kind_translation import (
    kind_set_inventory,
    kind_translation_frame,
    kind_translation_summary,
    shared_kind_comparison,
)
from .stats import MIN_PAIRS_FOR_PVALUE, paired_tests

V6_VARIANT = "V6"
COMPARE_TO = ("V1", "V5")
A4_VARIANTS = ("V0", "V1", "V2", "V3", "V4", "V5")

# Metrics valid for V6 (exclude missing-table fields per N1).
V6_SHARED_METRICS: Tuple[str, ...] = (
    "local_context_final",
    "local_context_AUC",
    "compressed_global_context_final",
    "allocation_entropy_by_kind",
    "allocation_entropy_by_zone",
)

V5_NOVEL_LOCS_DEFAULT = [
    "ControlLoadRootAndNonce@inst_control.zir:35",
    "ControlLoadRootAndNonce@inst_control.zir:44",
    "ControlLoadRootAndNonce@inst_control.zir:45",
    "ControlMRET@inst_control.zir:93",
]


def _load_v5_novel_locs(root: Optional[Path] = None) -> List[str]:
    path = (root or Path(__file__).resolve().parents[1]) / "v5_novel_contexts.json"
    if path.is_file():
        data = json.loads(path.read_text())
        return list(data.get("novel_locs_union_vs_v1", V5_NOVEL_LOCS_DEFAULT))
    return V5_NOVEL_LOCS_DEFAULT


def _variant_loc_union(
    variant: str,
    dbs_root: Optional[Path] = None,
    *,
    normalized: bool = False,
) -> Set[str]:
    mapping = discover_dbs(dbs_root, variants=(variant,)) if dbs_root else discover_dbs(variants=(variant,))
    union: Set[str] = set()
    for db in mapping.get(variant, {}).values():
        with sqlite3.connect(db) as conn:
            if normalized:
                union |= read_normalized_constraint_locs(conn)
            else:
                from .metrics import _read_constraint_locs
                union |= _read_constraint_locs(conn)
    return union


def _a4_reachable_union(
    dbs_root: Optional[Path] = None,
    *,
    normalized: bool = False,
) -> Set[str]:
    """Union of constraint_locs hit by any V0–V5 seed (50 A4 DBs)."""
    mapping = discover_dbs(dbs_root, variants=A4_VARIANTS) if dbs_root else discover_dbs(variants=A4_VARIANTS)
    union: Set[str] = set()
    for variant in A4_VARIANTS:
        for db in mapping.get(variant, {}).values():
            with sqlite3.connect(db) as conn:
                if normalized:
                    union |= read_normalized_constraint_locs(conn)
                else:
                    from .metrics import _read_constraint_locs
                    union |= _read_constraint_locs(conn)
    return union


def _read_cgc_keys(conn: sqlite3.Connection) -> Set[str]:
    try:
        return {r[0] for r in conn.execute("SELECT ctx_key FROM compressed_global_coverage").fetchall()}
    except sqlite3.OperationalError:
        return set()


def _variant_cgc_union(variant: str, dbs_root: Optional[Path] = None) -> Set[str]:
    mapping = discover_dbs(dbs_root, variants=(variant,)) if dbs_root else discover_dbs(variants=(variant,))
    union: Set[str] = set()
    for db in mapping.get(variant, {}).values():
        with sqlite3.connect(db) as conn:
            union |= _read_cgc_keys(conn)
    return union


def _a4_cgc_union(dbs_root: Optional[Path] = None) -> Set[str]:
    mapping = discover_dbs(dbs_root, variants=A4_VARIANTS) if dbs_root else discover_dbs(variants=A4_VARIANTS)
    union: Set[str] = set()
    for variant in A4_VARIANTS:
        for db in mapping.get(variant, {}).values():
            with sqlite3.connect(db) as conn:
                union |= _read_cgc_keys(conn)
    return union


def v6_vs_reference_frame(
    metrics: pd.DataFrame,
    references: Tuple[str, ...] = COMPARE_TO,
) -> pd.DataFrame:
    """Per-metric mean deltas V6 vs V1/V5 on paired seeds only."""
    v6 = metrics[metrics["variant"] == V6_VARIANT]
    if v6.empty:
        return pd.DataFrame()

    rows: List[dict] = []
    for ref in references:
        ref_df = metrics[metrics["variant"] == ref]
        common_seeds = sorted(set(v6["seed"]) & set(ref_df["seed"]))
        for metric in V6_SHARED_METRICS:
            v6_vals = v6.set_index("seed").loc[common_seeds, metric].astype(float)
            ref_vals = ref_df.set_index("seed").loc[common_seeds, metric].astype(float)
            mask = ~(v6_vals.isna() | ref_vals.isna())
            if mask.sum() == 0:
                continue
            xv = v6_vals[mask].to_numpy()
            yv = ref_vals[mask].to_numpy()
            rows.append({
                "variant": V6_VARIANT,
                "reference": ref,
                "metric": metric,
                "n_pairs": int(mask.sum()),
                "v6_mean": float(np.mean(xv)),
                "reference_mean": float(np.mean(yv)),
                "mean_diff": float(np.mean(xv - yv)),
                "mean_diff_pct": (
                    100.0 * float(np.mean(xv - yv)) / float(np.mean(yv))
                    if float(np.mean(yv)) != 0
                    else float("nan")
                ),
                "small_n_caveat": int(mask.sum()) < MIN_PAIRS_FOR_PVALUE,
            })
    return pd.DataFrame(rows)


def v6_paired_tests_frame(
    metrics: pd.DataFrame,
    references: Tuple[str, ...] = COMPARE_TO,
) -> pd.DataFrame:
    """Paired tests V6 vs V1/V5; p-values NaN when n<5 (N2)."""
    sub = metrics[metrics["variant"].isin((V6_VARIANT,) + references)]
    rows: List[dict] = []
    for ref in references:
        pt = paired_tests(sub, reference=ref, metrics=V6_SHARED_METRICS)
        v6_pt = pt[pt["variant"] == V6_VARIANT]
        rows.append(v6_pt)
    if not rows:
        return pd.DataFrame()
    return pd.concat(rows, ignore_index=True)


def loc_overlap_frame(
    dbs_root: Optional[Path] = None,
    root: Optional[Path] = None,
) -> pd.DataFrame:
    """Constraint-loc set decomposition — raw + normalized keys."""
    v0 = _variant_loc_union("V0", dbs_root)
    v1 = _variant_loc_union("V1", dbs_root)
    v5 = _variant_loc_union("V5", dbs_root)
    v6 = _variant_loc_union("V6", dbs_root)
    a4_union = _a4_reachable_union(dbs_root)
    v5_novel = {normalize_constraint_loc(x) for x in _load_v5_novel_locs(root)}

    v0n = _variant_loc_union("V0", dbs_root, normalized=True)
    v1n = _variant_loc_union("V1", dbs_root, normalized=True)
    v5n = _variant_loc_union("V5", dbs_root, normalized=True)
    v6n = _variant_loc_union("V6", dbs_root, normalized=True)
    a4n = _a4_reachable_union(dbs_root, normalized=True)

    def _rows(prefix: str, sets: dict) -> List[dict]:
        out = []
        for name, s in sets.items():
            out.append({
                "keying": prefix,
                "set_name": name,
                "count": len(s),
                "sample_locs": ";".join(sorted(s)[:5]),
            })
        return out

    raw_sets = {
        "V0_union": v0,
        "V1_union": v1,
        "V5_union": v5,
        "V6_union": v6,
        "A4_reachable_union_V0_V5": a4_union,
        "V6_intersect_A4_reachable": v6 & a4_union,
        "V6_exclusive_vs_A4": v6 - a4_union,
        "V5_novel_4_union": v5_novel,
        "V5_novel_4_hit_by_V6": v6n & v5_novel,
        "V5_novel_4_missed_by_V6": v5_novel - v6n,
        "V6_intersect_V1": v6 & v1,
        "V6_intersect_V5": v6 & v5,
        "V1_exclusive_vs_V6": v1 - v6,
        "V5_exclusive_vs_V6": v5 - v6,
    }
    norm_sets = {
        "V0_union": v0n,
        "V1_union": v1n,
        "V5_union": v5n,
        "V6_union": v6n,
        "A4_reachable_union_V0_V5": a4n,
        "V6_intersect_A4_reachable": v6n & a4n,
        "V6_exclusive_vs_A4": v6n - a4n,
        "V5_novel_4_union": v5_novel,
        "V5_novel_4_hit_by_V6": v6n & v5_novel,
        "V5_novel_4_missed_by_V6": v5_novel - v6n,
        "V6_intersect_V1": v6n & v1n,
        "V6_intersect_V5": v6n & v5n,
        "V1_exclusive_vs_V6": v1n - v6n,
        "V5_exclusive_vs_V6": v5n - v6n,
    }
    return pd.DataFrame(_rows("raw", raw_sets) + _rows("normalized", norm_sets))


def apples_to_apples_frame(
    dbs_root: Optional[Path] = None,
) -> pd.DataFrame:
    """V6 coverage restricted to A4-reachable universe — raw and normalized loc keys + CGC."""
    v6 = _variant_loc_union("V6", dbs_root)
    a4 = _a4_reachable_union(dbs_root)
    v6n = _variant_loc_union("V6", dbs_root, normalized=True)
    a4n = _a4_reachable_union(dbs_root, normalized=True)
    reachable_raw = v6 & a4
    reachable_norm = v6n & a4n

    v6_cgc = _variant_cgc_union("V6", dbs_root)
    a4_cgc = _a4_cgc_union(dbs_root)
    cgc_reachable = v6_cgc & a4_cgc

    return pd.DataFrame([{
        "v6_full_coverage_raw": len(v6),
        "v6_a4_reachable_raw": len(reachable_raw),
        "v6_exclusive_vs_a4_raw": len(v6 - a4),
        "v6_reachable_fraction_raw": len(reachable_raw) / len(v6) if v6 else float("nan"),
        "v6_full_coverage_normalized": len(v6n),
        "v6_a4_reachable_normalized": len(reachable_norm),
        "v6_exclusive_vs_a4_normalized": len(v6n - a4n),
        "a4_union_normalized": len(a4n),
        "v6_reachable_fraction_normalized": len(reachable_norm) / len(v6n) if v6n else float("nan"),
        "v6_exclusive_fraction_normalized": len(v6n - a4n) / len(v6n) if v6n else float("nan"),
        "v6_full_cgc": len(v6_cgc),
        "v6_a4_reachable_cgc": len(cgc_reachable),
        "v6_exclusive_cgc_vs_a4": len(v6_cgc - a4_cgc),
        "a4_cgc_union": len(a4_cgc),
        "v6_cgc_reachable_fraction": len(cgc_reachable) / len(v6_cgc) if v6_cgc else float("nan"),
        "v6_cgc_exclusive_fraction": len(v6_cgc - a4_cgc) / len(v6_cgc) if v6_cgc else float("nan"),
        "v6_seeds": len(
            (discover_dbs(dbs_root, variants=(V6_VARIANT,)) if dbs_root else discover_dbs(variants=(V6_VARIANT,)))
            .get(V6_VARIANT, {})
        ),
        "note": "Loc: use normalized columns. CGC: ctx_key overlap (schema-compatible, distribution differs).",
    }])


def a4_territory_coverage_frame(
    dbs_root: Optional[Path] = None,
) -> pd.DataFrame:
    """Locs each variant finds within the 51-loc A4-reachable normalized union."""
    a4 = _a4_reachable_union(dbs_root, normalized=True)
    a4_size = len(a4)
    rows: List[dict] = []
    for variant in ("V1", "V5", "V6"):
        union = _variant_loc_union(variant, dbs_root, normalized=True)
        in_territory = union & a4
        rows.append({
            "variant": variant,
            "locs_in_a4_territory": len(in_territory),
            "a4_territory_size": a4_size,
            "territory_coverage_pct": 100.0 * len(in_territory) / a4_size if a4_size else float("nan"),
            "full_union_size": len(union),
            "v6_seeds": (
                len((discover_dbs(dbs_root, variants=("V6",)) if dbs_root else discover_dbs(variants=("V6",)))
                    .get("V6", {}))
                if variant == "V6" else 10
            ),
        })
    return pd.DataFrame(rows)


def v5_novel_overlap_frame(
    dbs_root: Optional[Path] = None,
    root: Optional[Path] = None,
) -> pd.DataFrame:
    """Per-loc hit table for V5's 4 novel contexts vs V5/V6 unions."""
    novel = _load_v5_novel_locs(root)
    v5n = _variant_loc_union("V5", dbs_root, normalized=True)
    v6n = _variant_loc_union("V6", dbs_root, normalized=True)
    rows: List[dict] = []
    for raw in novel:
        key = normalize_constraint_loc(raw)
        rows.append({
            "constraint_loc_a4": raw,
            "constraint_loc_normalized": key,
            "in_v5_union": key in v5n,
            "in_v6_union": key in v6n,
            "v5_novel_hit": key in v5n,
            "v6_hit": key in v6n,
        })
    return pd.DataFrame(rows)


def build_v6_outputs(
    metrics: pd.DataFrame,
    dbs_root: Optional[Path] = None,
    root: Optional[Path] = None,
) -> Dict[str, pd.DataFrame]:
    """All Batch 3 CSV payloads."""
    per_seed_kinds = kind_translation_frame(dbs_root)
    kind_sum = kind_translation_summary(per_seed_kinds)
    kind_inv = kind_set_inventory(kind_sum)

    return {
        "v6_vs_v1_v5": v6_vs_reference_frame(metrics),
        "v6_paired_tests": v6_paired_tests_frame(metrics),
        "loc_overlap": loc_overlap_frame(dbs_root, root),
        "apples_to_apples": apples_to_apples_frame(dbs_root),
        "kind_translation": kind_sum,
        "kind_inventory": kind_inv,
        "shared_kind_rates": shared_kind_comparison(kind_sum),
        "territory_coverage": a4_territory_coverage_frame(dbs_root),
        "v5_novel_overlap": v5_novel_overlap_frame(dbs_root, root),
    }

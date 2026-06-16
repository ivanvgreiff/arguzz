"""Phase 9.4 supplement — discovery rate per 1000 mutations by kind (IV.POS.5 §17.1)."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from .counterfactuals import KINDS
from .discover import discover_dbs

DEFAULT_DBS_ROOT = Path(__file__).resolve().parents[1] / "dbs"


def _kind_pulls_and_discoveries(db_path: Path) -> Dict[str, Dict[str, int]]:
    pulls = {k: 0 for k in KINDS}
    discoveries = {k: 0 for k in KINDS}
    with sqlite3.connect(db_path) as conn:
        for kind, n in conn.execute(
            "SELECT kind, COUNT(*) FROM mutations GROUP BY kind"
        ):
            if kind in pulls:
                pulls[kind] = int(n)
        for _loc, mid in conn.execute(
            "SELECT constraint_loc, first_hit_mutation_id FROM coverage"
        ):
            row = conn.execute(
                "SELECT kind FROM mutations WHERE id = ?", (mid,)
            ).fetchone()
            if row and row[0] in discoveries:
                discoveries[row[0]] += 1
    return {"pulls": pulls, "discoveries": discoveries}


def discovery_rate_by_kind_frame(
    dbs_root: Optional[Path] = None,
    variants: tuple[str, ...] = ("V1", "V2", "V3", "V4", "V5"),
) -> pd.DataFrame:
    """Per (variant, kind): total pulls, first-hit credits, rate per 1000 pulls."""
    root = dbs_root or DEFAULT_DBS_ROOT
    mapping = discover_dbs(root)
    rows: List[dict] = []
    for variant in variants:
        for seed, db in sorted(mapping[variant].items()):
            stats = _kind_pulls_and_discoveries(db)
            for kind in KINDS:
                pulls = stats["pulls"][kind]
                disc = stats["discoveries"][kind]
                rate = (1000.0 * disc / pulls) if pulls else float("nan")
                rows.append(
                    {
                        "variant": variant,
                        "seed": seed,
                        "kind": kind,
                        "pulls": pulls,
                        "discoveries": disc,
                        "discovery_rate_per_1k": rate,
                    }
                )
    return pd.DataFrame(rows)


def discovery_rate_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Pool pulls and discoveries per (variant, kind) across seeds."""
    if df.empty:
        return df
    agg = (
        df.groupby(["variant", "kind"])[["pulls", "discoveries"]]
        .sum()
        .reset_index()
    )
    agg["discovery_rate_per_1k"] = agg.apply(
        lambda r: (1000.0 * r["discoveries"] / r["pulls"]) if r["pulls"] else float("nan"),
        axis=1,
    )
    return agg.sort_values(["variant", "kind"]).reset_index(drop=True)


def discovery_rate_v1_vs_v5_delta(summary: pd.DataFrame) -> pd.DataFrame:
    """V5 minus V1 discovery rate per kind (for notebook heatmap)."""
    v1 = summary[summary.variant == "V1"].set_index("kind")
    v5 = summary[summary.variant == "V5"].set_index("kind")
    rows: List[dict] = []
    for kind in KINDS:
        if kind not in v1.index or kind not in v5.index:
            continue
        rows.append(
            {
                "kind": kind,
                "v1_pulls": int(v1.loc[kind, "pulls"]),
                "v1_discoveries": int(v1.loc[kind, "discoveries"]),
                "v1_rate_per_1k": float(v1.loc[kind, "discovery_rate_per_1k"]),
                "v5_pulls": int(v5.loc[kind, "pulls"]),
                "v5_discoveries": int(v5.loc[kind, "discoveries"]),
                "v5_rate_per_1k": float(v5.loc[kind, "discovery_rate_per_1k"]),
                "delta_pulls": int(v5.loc[kind, "pulls"] - v1.loc[kind, "pulls"]),
                "delta_rate_per_1k": float(
                    v5.loc[kind, "discovery_rate_per_1k"]
                    - v1.loc[kind, "discovery_rate_per_1k"]
                ),
            }
        )
    return pd.DataFrame(rows)

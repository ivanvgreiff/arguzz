"""Per-constraint_loc local_coverage_v2 cell counts (wide vs deep diagnostic)."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import List, Optional

import pandas as pd

from .discover import discover_dbs

DEFAULT_DBS_ROOT = Path(__file__).resolve().parents[1] / "dbs"


def per_loc_v2_cells_frame(
    dbs_root: Optional[Path] = None,
    variants: tuple[str, ...] = ("V1", "V2", "V3", "V4", "V5"),
) -> pd.DataFrame:
    """Per (variant, seed, constraint_loc): COUNT(*) from local_coverage_v2."""
    root = dbs_root or DEFAULT_DBS_ROOT
    mapping = discover_dbs(root)
    rows: List[dict] = []
    for variant in variants:
        for seed, db in sorted(mapping[variant].items()):
            with sqlite3.connect(db) as conn:
                for loc, n in conn.execute(
                    """
                    SELECT constraint_loc, COUNT(*) AS n
                    FROM local_coverage_v2
                    GROUP BY constraint_loc
                    """
                ):
                    rows.append(
                        {
                            "variant": variant,
                            "seed": seed,
                            "constraint_loc": loc,
                            "v2_cell_count": int(n),
                        }
                    )
    return pd.DataFrame(rows)


def per_loc_v2_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Mean v2 cells per loc across seeds (wide-vs-deep comparison)."""
    if df.empty:
        return df
    return (
        df.groupby(["variant", "constraint_loc"])["v2_cell_count"]
        .agg(mean_v2_cells="mean", std_v2_cells="std", seeds_present="count")
        .reset_index()
        .sort_values(["variant", "constraint_loc"])
    )
